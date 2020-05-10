using K4os.Compression.LZ4;
using NsoElfConverterDotNet.Structures;
using NsoElfConverterDotNet.Structures.Elf;
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace NsoElfConverterDotNet.Nx2elf
{
    public class NsoFile
    {
        public NsoFile(ReadOnlySpan<byte> data)
        {
            if (data.Length < NsoHeader.Length)
            {
                throw new ArgumentException("NSO data is smaller than the header", nameof(data));
            }

            Header = new NsoHeader(data.Slice(0, NsoHeader.Length));

            // assume segments are after each other and mem offsets are aligned
            // note: there are also symbols "_start" and "end" which describe
            // the total size.
            var dataSegment = Header.Segments[(int)NsoSegmentType.Data];
            var imageSize = dataSegment.MemoryOffset + dataSegment.MemorySize + dataSegment.AlignOrTotalSz;
            Image = new byte[imageSize];

            for (int i = 0; i < 3; i++)
            {
                var segment = Header.Segments[i];
                var fileSize = Header.SegmentFileSizes[i];

                var compressed = data.Slice((int)segment.FileOffset, (int)fileSize);
                var decompressed = Image.AsSpan().Slice((int)segment.MemoryOffset, (int)segment.MemorySize);
                var decompressedSize = LZ4Codec.Decode(compressed, decompressed);
                if (decompressedSize <= 0)
                {
                    throw new Exception($"Failed to decompressed segment {i}.");
                }
            }

            var modPtr = new ModPointer(Image);
            var modBaseRaw = (int)modPtr.MaskOffset;
            var modBase = Image.AsSpan().Slice(modBaseRaw);
            var mod = new ModHeader(modBase);

            DynInfo = new DynInfoData();
            DynOffset = modBaseRaw + mod.DynamicOffset;
            var dynamic = new Elf64Dyn(Image.AsSpan().Slice(DynOffset));
            var dynamicIndex = 0;
            while (dynamic.Tag != default)
            {
                switch (dynamic.Tag)
                {
                    case ElfConstants.DT_SYMTAB:
                        DynInfo.SymTab = dynamic.Un;
                        break;
                    case ElfConstants.DT_RELA:
                        DynInfo.Rela = dynamic.Un;
                        break;
                    case ElfConstants.DT_RELASZ:
                        DynInfo.RelaSize = dynamic.Un;
                        break;
                    case ElfConstants.DT_JMPREL:
                        DynInfo.JumpRel = dynamic.Un;
                        break;
                    case ElfConstants.DT_PLTRELSZ:
                        DynInfo.PltRelSize = dynamic.Un;
                        break;
                    case ElfConstants.DT_STRTAB:
                        DynInfo.StrTab = dynamic.Un;
                        break;
                    case ElfConstants.DT_STRSZ:
                        DynInfo.StrSize = dynamic.Un;
                        break;
                    case ElfConstants.DT_PLTGOT:
                        DynInfo.PltGot = dynamic.Un;
                        break;
                    case ElfConstants.DT_HASH:
                        DynInfo.Hash = dynamic.Un;
                        break;
                    case ElfConstants.DT_GNU_HASH:
                        DynInfo.GnuHash = dynamic.Un;
                        break;
                    case ElfConstants.DT_INIT:
                        DynInfo.Init = dynamic.Un;
                        break;
                    case ElfConstants.DT_FINI:
                        DynInfo.Fini = dynamic.Un;
                        break;
                    case ElfConstants.DT_INIT_ARRAY:
                        DynInfo.InitArray = dynamic.Un;
                        break;
                    case ElfConstants.DT_INIT_ARRAYSZ:
                        DynInfo.InitArraySize = dynamic.Un;
                        break;
                    case ElfConstants.DT_FINI_ARRAY:
                        DynInfo.FiniArray = dynamic.Un;
                        break;
                    case ElfConstants.DT_FINI_ARRAYSZ:
                        DynInfo.FiniArraySize = dynamic.Un;
                        break;
                }

                dynamicIndex += 1;
                dynamic = new Elf64Dyn(Image.AsSpan().Slice(DynOffset + dynamicIndex * Elf64Dyn.Length));
            }

            // Resolve Plt
            var textSegment = Header.Segments[(int)NsoSegmentType.Text];
            var textSegmentData = Image.AsSpan().Slice((int)textSegment.MemoryOffset, (int)textSegment.MemorySize);
            if (DynInfo.PltRelSize != default)
            {
                var pltPattern = new byte[]
                {
                    0xf0, 0x7b, 0xbf, 0xa9,
                    0xd0, 0x04, 0x00, 0xd0,
                    0x11, 0x8a, 0x42, 0xf9,
                    0x10, 0x42, 0x14, 0x91,

                    0x20, 0x02, 0x1f, 0xd6,
                    0x1f, 0x20, 0x03, 0xd5,
                    0x1f, 0x20, 0x03, 0xd5,
                    0x1f, 0x20, 0x03, 0xd5
                };
                var pltMask = new byte[]
                {
                    0xff, 0xff, 0xff, 0xff,
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0xff,
                    0x00, 0x00, 0x00, 0xff,
                    0x00, 0x00, 0x00, 0xff,
                    0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff
                };
                var found = MemoryLocateWithMask(textSegmentData, textSegmentData.Length, pltPattern, pltMask, pltPattern.Length);
                if (found > -1)
                {
                    PltInfoAddr = (ulong)found + textSegment.MemoryOffset;
                    // Assume the plt exactly matches .rela.plt
                    var pltEntryCount = DynInfo.PltRelSize / Elf64Rela.Length;
                    const int pltEntrySize = 16;
                    PltInfoSize = pltEntrySize * 2 + pltEntrySize * pltEntryCount;
                }
            }

            // Search for a GnuBuildId struct by the contained Elf64Header and 4-char owner string
            // Kinda gross, but hopefully unique enough to avoid false positives...
            var md5BuildIdNeedle = new byte[] { 4, 0, 0, 0 /* sizeof(GnuBuildId::owner) */,  16, 0, 0, 0 /* sizeof(GnuBuildId::build_id_md5) */, 3, 0, 0, 0,
                71 /* G */, 78 /* N */, 85 /* U */, 0 };
            var sha1BuildIdNeedle = new byte[] { 4, 0, 0, 0  /* sizeof(GnuBuildId::owner) */ , 20, 0, 0, 0  /* sizeof(GnuBuildId::build_id_sha1) */, 3, 0, 0, 0,
                71 /* G */, 78 /* N */, 85 /* U */, 0 };
            foreach (var segmentType in new[] { NsoSegmentType.Rodata, NsoSegmentType.Text, NsoSegmentType.Data })
            {
                var segment = Header.Segments[(int)segmentType];
                var segmentData = Image.AsSpan().Slice((int)segment.MemoryOffset, (int)segment.MemorySize);
                var noteOffset = MemoryLocateReverse(segmentData, segmentData.Length, md5BuildIdNeedle, md5BuildIdNeedle.Length);
                if (noteOffset == -1)
                {
                    noteOffset = MemoryLocateReverse(segmentData, segmentData.Length, sha1BuildIdNeedle, sha1BuildIdNeedle.Length);
                }

                if (noteOffset != -1)
                {
                    Note = new Elf64Nhdr(Image.AsSpan().Slice((int)segment.MemoryOffset + noteOffset));
                    NoteOffset = (int)segment.MemoryOffset + noteOffset;
                }
            }

            static int mod_get_offset(int modBaseRaw, int relative_offset)
            {
                return modBaseRaw + relative_offset;
            };

            EhInfoHdrAddr = mod_get_offset(modBaseRaw, (int)mod.EhStartOffset);
            EhInfoHdrSize = mod_get_offset(modBaseRaw, (int)mod.EhEndOffset) - EhInfoHdrAddr;
        }

        public NsoHeader Header { get; }

        private byte[] Image { get; }
        private DynInfoData DynInfo { get; }
        private int DynOffset { get; }
        private Elf64Nhdr? Note { get; }
        private int NoteOffset { get; }
        private ulong PltInfoAddr { get; }
        private ulong PltInfoSize { get; }
        private int EhInfoHdrAddr { get; }
        private int EhInfoHdrSize { get; }

        private void IterateDynamic(Action<Elf64Sym, uint> action)
        {
            for (uint i = 0; i < Header.DynSym.Size / Elf64Sym.Length; i++)
            {
                var sym = new Elf64Sym(Image.AsSpan().Slice((int)DynInfo.SymTab + Elf64Sym.Length * (int)i));
                action(sym, i);
            }
        }

        public byte[] ToElf()
        {
            var shstrtab = new StringTable();
            shstrtab.AddString(".shstrtab");

            // Profile sections based on dynsym
            UInt16 numShdrs = 0;
            var knownSections = new Dictionary<UInt16, Elf64Shdr>();

            Elf64Shdr vaddrToShdr(ulong vaddr)
            {
                var shdr = new Elf64Shdr();
                for (int i = 0; i < 3; i++)
                {
                    var location = vaddr;
                    var segment = Header.Segments[i];
                    var segmentMemoryEnd = segment.MemoryOffset + segment.MemorySize;
                    // sh_offset will be fixed up later
                    if (location >= segment.MemoryOffset && location < segmentMemoryEnd)
                    {
                        // .text, .data, .rodata
                        string name = "";
                        shdr.Type = ElfConstants.SHT_PROGBITS;
                        switch (i)
                        {
                            case (int)NsoSegmentType.Text:
                                shdr.Flags = ElfConstants.SHF_ALLOC | ElfConstants.SHF_EXECINSTR;
                                name = ".text";
                                break;
                            case (int)NsoSegmentType.Data:
                                shdr.Flags = ElfConstants.SHF_ALLOC | ElfConstants.SHF_WRITE;
                                name = ".data";
                                break;
                            case (int)NsoSegmentType.Rodata:
                                shdr.Flags = ElfConstants.SHF_ALLOC;
                                name = ".rodata";
                                break;
                        }
                        shstrtab.AddString(name);
                        shdr.Name = shstrtab.GetOffset(name);
                        shdr.Addr = segment.MemoryOffset;
                        shdr.Size = segment.MemorySize;
                        shdr.AddrAlign = sizeof(UInt64);
                    }
                    else if (i == (int)NsoSegmentType.Data && location >= segmentMemoryEnd && location < segmentMemoryEnd + segment.AlignOrTotalSz)
                    {
                        // .bss
                        var name = ".bss";
                        shstrtab.AddString(name);
                        shdr.Name = shstrtab.GetOffset(name);
                        shdr.Type = ElfConstants.SHT_NOBITS;
                        shdr.Flags = ElfConstants.SHF_ALLOC | ElfConstants.SHF_WRITE;
                        shdr.Addr = segmentMemoryEnd;
                        shdr.Size = segment.AlignOrTotalSz;
                        shdr.AddrAlign = sizeof(UInt64);
                    }
                }
                return shdr;
            }

            IterateDynamic((sym, i) =>
            {
                if (sym.Shndx >= ElfConstants.SHN_LORESERVE)
                {
                    return;
                }

                numShdrs = (ushort)Math.Max(numShdrs, sym.Shndx);
                if (sym.Shndx != ElfConstants.SHT_NULL && knownSections.Count(kv => kv.Key == sym.Shndx) == 0)
                {
                    var shdr = vaddrToShdr(sym.Value);
                    if (shdr.Type != ElfConstants.SHT_NULL)
                    {
                        knownSections[sym.Shndx] = shdr;
                    }
                    else
                    {
                        throw new Exception($"Failed to make SHDR for Shndx {sym.Shndx}.");
                    }
                }
            });

            // Check if we need to manually add the known segments (nothing was pointing to them,
            // so they can go anywhere).
            if (knownSections.Count != 4)
            {
                ushort nextFree(ushort start)
                {
                    for (ushort i = (ushort)(start + 1); i < ElfConstants.SHN_LORESERVE; i++)
                    {
                        if (!knownSections.ContainsKey(i))
                        {
                            return i;
                        }
                    }
                    return ElfConstants.SHN_UNDEF;
                }

                var shndx = nextFree(ElfConstants.SHN_UNDEF);
                if (shndx != ElfConstants.SHN_UNDEF && shstrtab.GetOffset(".text") == 0 && Header.Segments[(int)NsoSegmentType.Text].MemorySize > 0)
                {
                    knownSections[shndx] = vaddrToShdr(Header.Segments[(int)NsoSegmentType.Text].MemoryOffset);
                    shndx = nextFree(shndx);
                }
                if (shndx != ElfConstants.SHN_UNDEF && shstrtab.GetOffset(".rodata") == 0 && Header.Segments[(int)NsoSegmentType.Rodata].MemorySize > 0)
                {
                    knownSections[shndx] = vaddrToShdr(Header.Segments[(int)NsoSegmentType.Rodata].MemoryOffset);
                    shndx = nextFree(shndx);
                }
                if (shndx != ElfConstants.SHN_UNDEF && shstrtab.GetOffset(".data") == 0 && Header.Segments[(int)NsoSegmentType.Data].MemorySize > 0)
                {
                    knownSections[shndx] = vaddrToShdr(Header.Segments[(int)NsoSegmentType.Data].MemoryOffset);
                    shndx = nextFree(shndx);
                }
                if (shndx != ElfConstants.SHN_UNDEF && shstrtab.GetOffset(".bss") == 0 && Header.Segments[(int)NsoSegmentType.Data].AlignOrTotalSz > 0)
                {
                    knownSections[shndx] = vaddrToShdr(Header.Segments[(int)NsoSegmentType.Data].MemoryOffset + Header.Segments[(int)NsoSegmentType.Data].MemorySize);
                    shndx = nextFree(shndx);
                }
            }

            // +1 to go from index -> count
            numShdrs += 1;

            // Determine how many other sections are needed
            int shdrsNeeded = knownSections.Count - numShdrs;
            // index 0
            shdrsNeeded += 1;
            // .shstrtab
            shdrsNeeded += 1;
            // Assume the following will always be present: .dynstr, .dynsym, .dynamic, .rela.dyn
            foreach (var name in new[] { ".dynstr", ".dynsym", ".dynamic", ".rela.dyn" })
            {
                shstrtab.AddString(name);
                shdrsNeeded += 1;
            }

            // In the original implementation of nx2elf, present was a struct
            // This has been turned into simple variables here because those suffice
            bool present_plt = false;
            bool present_got = false;
            bool present_got_plt = false;
            bool present_rela_plt = false;
            bool present_hash = false;
            bool present_gnu_hash = false;
            bool present_init = false;
            bool present_fini = false;
            bool present_init_array = false;
            bool present_fini_array = false;
            bool present_note = false;
            bool present_eh = false;

            void ALLOC_SHDR_IF(bool condition, ref bool name)
            {
                if (condition)
                {
                    name = true;
                    shdrsNeeded += 1;
                }
            }

            ALLOC_SHDR_IF(PltInfoAddr != 0, ref present_plt);
            var jumpSlotAddrEnd = 0;
            if (DynInfo.JumpRel != 0)
            {
                for (ulong i = 0; i < DynInfo.PltRelSize / Elf64Rela.Length; i++)
                {
                    var rela = new Elf64Rela(Image.AsSpan().Slice((int)(DynInfo.JumpRel + i * Elf64Rela.Length)));
                    if ((uint)rela.Info == ElfConstants.R_AARCH64_JUMP_SLOT)
                    {
                        jumpSlotAddrEnd = Math.Max(jumpSlotAddrEnd, (int)(rela.Offset + 8));
                    }
                }
            }
            ALLOC_SHDR_IF(jumpSlotAddrEnd != 0 && DynInfo.PltGot != 0, ref present_got_plt);

            var gotAddr = 0;
            if (jumpSlotAddrEnd != 0)
            {
                var gotDynamicPtr = BitConverter.GetBytes((ulong)DynOffset);
                var found = MemoryLocate(Image.AsSpan().Slice(jumpSlotAddrEnd), Image.Length - jumpSlotAddrEnd, gotDynamicPtr, gotDynamicPtr.Length);
                if (found > -1)
                {
                    gotAddr = found + jumpSlotAddrEnd;
                }
            }

            ALLOC_SHDR_IF(gotAddr != 0 && DynInfo.Rela != 0, ref present_got);
            ALLOC_SHDR_IF(present_got_plt && DynInfo.JumpRel != 0 && DynInfo.PltRelSize != 0, ref present_rela_plt);
            ALLOC_SHDR_IF(DynInfo.Hash != 0, ref present_hash);
            ALLOC_SHDR_IF(DynInfo.GnuHash != 0, ref present_gnu_hash);
            ALLOC_SHDR_IF(DynInfo.InitArray != 0 && DynInfo.InitArraySize != 0, ref present_init_array);
            ALLOC_SHDR_IF(DynInfo.FiniArray != 0 && DynInfo.FiniArraySize != 0, ref present_fini_array);
            ALLOC_SHDR_IF(Note.HasValue, ref present_note);

            var initRetOffset = 0;
            if (DynInfo.Init != 0)
            {
                var initPtr = Image.AsSpan().Slice((int)DynInfo.Init);
                for (int i = 0; /* no max */ ; i++)
                {
                    if (BinaryPrimitives.ReadUInt32LittleEndian(initPtr.Slice(i * 4)) == 0xd65f03c0ul)
                    {
                        initRetOffset = (i + 1) * 4;
                        break;
                    }
                }
                ALLOC_SHDR_IF(initRetOffset != 0, ref present_init);
            }

            var finiBranchOffset = 0;
            if (DynInfo.Fini != 0)
            {
                var finiPtr = Image.AsSpan().Slice((int)DynInfo.Fini);
                for (int i = 0; i < 0x20; i++)
                {
                    if ((BinaryPrimitives.ReadUInt32LittleEndian(finiPtr.Slice(i * 4)) & 0xff000000ul) == 0x14000000ul)
                    {
                        finiBranchOffset = (i + 1) * 4;
                        break;
                    }
                }
                ALLOC_SHDR_IF(finiBranchOffset != 0, ref present_fini);
            }

            uint ehInfoHdrSize = 0;
            if (ElfEHInfo.MeasureFrame(Image, EhInfoHdrAddr, out uint ehInfoFrameAddr, out uint ehInfoFrameSize))
            {
                // XXX the alignment of sizes is a fudge...
                ehInfoHdrSize = (uint)ALIGN_UP(this.EhInfoHdrSize, 0x10);
                ehInfoFrameSize = (uint)ALIGN_UP(ehInfoFrameSize, 0x10);
                present_eh = true;
                // Account for .eh_frame_hdr and .eh_frame
                shdrsNeeded += 2;
                shstrtab.AddString(".eh_frame_hdr");
                shstrtab.AddString(".eh_frame");
            }

            if (present_plt) shstrtab.AddString(".plt");
            if (present_got) shstrtab.AddString(".got");
            if (present_got_plt) shstrtab.AddString(".got.plt");
            if (present_rela_plt) shstrtab.AddString(".rela.plt");
            if (present_hash) shstrtab.AddString(".hash");
            if (present_gnu_hash) shstrtab.AddString(".gnu.hash");
            if (present_init) shstrtab.AddString(".init");
            if (present_fini) shstrtab.AddString(".fini");
            if (present_init_array) shstrtab.AddString(".init_array");
            if (present_fini_array) shstrtab.AddString(".fini_array");
            if (present_note) shstrtab.AddString(".note");

            shstrtab.Build();
            if (shdrsNeeded > 0)
            {
                numShdrs += (ushort)shdrsNeeded;
            }

            // Add dynamic and EH segments
            var numPhdrs = 5;

            int elfSize = Elf64Ehdr.Length + Elf64Phdr.Length * numPhdrs + Elf64Shdr.Length * numShdrs;
            elfSize += shstrtab.Size;
            foreach (var segment in Header.Segments)
            {
                elfSize += (int)segment.MemorySize;
            }

            var elf = new byte[elfSize];
            var ehdr = new Elf64Ehdr();
            ehdr.Ident = new byte[]{
                0x7f, 0x45, 0x4C, 0x46, // 0x7F E L F
                2, // ELFCLASS64
                1, // ELFDATA2LSB (little endian)
                1, // EV_CURRENT
                0, // ELFOSABI_NONE (UNIX System V ABI)
                0 };
            ehdr.Type = ElfConstants.ET_DYN; // ET_DYN
            ehdr.Machine = ElfConstants.EM_AARCH64;
            ehdr.Version = ElfConstants.EV_CURRENT;
            ehdr.EhSize = Elf64Ehdr.Length;
            ehdr.Flags = 0;
            ehdr.Entry = Header.Segments[(int)NsoSegmentType.Text].MemoryOffset;
            ehdr.PhOff = ehdr.EhSize;
            ehdr.PHEntSize = Elf64Phdr.Length;
            ehdr.PHNum = (ushort)numPhdrs;
            ehdr.ShOff = ehdr.PhOff + (ulong)ehdr.PHEntSize * ehdr.PHNum;
            ehdr.SHEntSize = Elf64Shdr.Length;
            ehdr.SHNum = numShdrs;
            ehdr.SHStrNdx = ElfConstants.SHN_UNDEF;

            // IDA only _needs_ phdrs and dynamic phdr to give good results
            var phdrsStart = elf.AsSpan().Slice((int)ehdr.PhOff);
            var phdrs = new Elf64Phdr();

            ulong vaddr_to_foffset(ulong vaddr)
            {
                var phdrsStart = elf.AsSpan().Slice((int)ehdr.PhOff);
                for (int i = 0; i < 3; i++)
                {
                    var phdrStart = phdrsStart.Slice(i * Elf64Phdr.Length);
                    var phdr = new Elf64Phdr(phdrStart);
                    if (vaddr >= phdr.VAddr && vaddr < phdr.VAddr + phdr.FileSize)
                    {
                        return phdr.Offset + (vaddr - phdr.VAddr);
                    }
                }
                return 0;
            };

            shstrtab.Offset = (int)ehdr.ShOff + (int)ehdr.SHEntSize * (int)ehdr.SHNum;
            shstrtab.Buffer.CopyTo(elf.AsSpan().Slice(shstrtab.Offset));

            var data_offset_cur = shstrtab.Offset + shstrtab.Size;
            for (var i = 0; i < numPhdrs; i++)
            {
                var phdrStart = phdrsStart.Slice(i * Elf64Phdr.Length);
                var phdr = new Elf64Phdr();
                if (i < 3)
                {
                    var seg = Header.Segments[i];
                    phdr.Type = ElfConstants.PT_LOAD;
                    switch (i)
                    {
                        case (int)NsoSegmentType.Text: phdr.Flags = ElfConstants.PF_R | ElfConstants.PF_X; break;
                        case (int)NsoSegmentType.Rodata: phdr.Flags = ElfConstants.PF_R; break;
                        case (int)NsoSegmentType.Data: phdr.Flags = ElfConstants.PF_R | ElfConstants.PF_W; break;
                    }
                    phdr.VAddr = phdr.PAddr = seg.MemoryOffset;
                    phdr.Offset = (ulong)data_offset_cur;
                    phdr.FileSize = seg.MemorySize;
                    if (i == (int)NsoSegmentType.Data)
                    {
                        phdr.MemSize = seg.MemorySize + seg.AlignOrTotalSz;
                        phdr.Align = 1;
                    }
                    else
                    {
                        phdr.MemSize = seg.MemorySize;
                        phdr.Align = seg.AlignOrTotalSz;
                    }

                    Image.AsSpan().Slice((int)seg.MemoryOffset, (int)seg.MemorySize).CopyTo(elf.AsSpan().Slice((int)phdr.Offset));

                    // fixup sh_offset
                    foreach (var known_section in knownSections)
                    {
                        if (known_section.Value.Addr == phdr.VAddr)
                        {
                            knownSections[known_section.Key].Offset = phdr.Offset;
                        }
                    }

                    data_offset_cur += (int)phdr.FileSize;
                }
                else if (i == (int)NsoSegmentType.Data + 1)
                {
                    phdr.Type = ElfConstants.PT_DYNAMIC;
                    phdr.Flags = ElfConstants.PF_R | ElfConstants.PF_W;
                    phdr.VAddr = phdr.PAddr = (ulong)DynOffset;
                    phdr.Offset = vaddr_to_foffset(phdr.VAddr);
                    var dyn_size = Elf64Dyn.Length;

                    var dynOffset = this.DynOffset;
                    var dynamic = new Elf64Dyn(Image.AsSpan().Slice(DynOffset));
                    while (dynamic.Tag != 0)
                    {
                        dyn_size += Elf64Dyn.Length;
                        dynOffset += Elf64Dyn.Length;
                        dynamic = new Elf64Dyn(Image.AsSpan().Slice(dynOffset));
                    }
                    phdr.FileSize = phdr.MemSize = (ulong)dyn_size;
                    phdr.Align = 8;
                }
                else if (i == (int)NsoSegmentType.Data + 2)
                {
                    // Too bad ida doesn't fucking use it!
                    phdr.Type = ElfConstants.PT_GNU_EH_FRAME;
                    phdr.Flags = ElfConstants.PF_R;
                    phdr.VAddr = phdr.PAddr = (ulong)EhInfoHdrAddr;
                    phdr.Offset = vaddr_to_foffset(phdr.VAddr);
                    phdr.FileSize = phdr.MemSize = (ulong)ehInfoHdrSize;
                    phdr.Align = 4;
                }
                phdr.Write(phdrStart);
            }

            // IDA's elf loader will also look for certain sections...
            // IMO this is IDA bug - it should just use PT_DYNAMIC
            // At least on 6.95, IDA will do a decent job if only PT_DYNAMIC is
            // there, but once SHT_DYNAMIC is added, then many entries which would
            // otherwise work fine by being only in the dynamic section, must also
            // have section headers...
            var shdrsStart = elf.AsSpan().Slice((int)ehdr.ShOff);
            // Insert sections for which section index was known
            foreach (var known_section in knownSections)
            {
                var currentShdrOffset = shdrsStart.Slice(known_section.Key * Elf64Shdr.Length);
                known_section.Value.Write(currentShdrOffset);
            }
            // Insert other handy sections at an available section index
            uint insert_shdr(Span<byte> shdrsStart, Elf64Shdr shdr, bool ordered = false)
            {
                uint start = 1;
                // This is basically a hack to convince ida not to delete segments
                if (ordered)
                {
                    foreach (var known_section in knownSections)
                    {
                        var known_shdr = known_section.Value;
                        if (shdr.Addr >= known_shdr.Addr &&
                            shdr.Addr < known_shdr.Addr + known_shdr.Size)
                        {
                            start = (uint)known_section.Key + 1;
                        }
                    }
                }
                retry:
                for (var i = start; i < numShdrs; i++)
                {
                    var currentShdrStart = shdrsStart.Slice((int)i * Elf64Shdr.Length);
                    var currentShdr = new Elf64Shdr(currentShdrStart);
                    if (currentShdr.Type == ElfConstants.SHT_NULL)
                    {
                        shdr.Write(currentShdrStart);
                        return i;
                    }
                }
                // failed to find open spot with restrictions, so try again at any location
                if (ordered && start != 1)
                {
                    Console.Error.WriteLine("warning: failed to meet ordering for sh_addr " + shdr.Addr.ToString("X"));
                    start = 1;
                    goto retry;
                }
                return ElfConstants.SHN_UNDEF;
            };

            Elf64Shdr shdr;
            if (present_init)
            {
                shdr = new Elf64Shdr();
                shdr.Name = shstrtab.GetOffset(".init");
                shdr.Type = ElfConstants.SHT_PROGBITS;
                shdr.Flags = ElfConstants.SHF_ALLOC | ElfConstants.SHF_EXECINSTR;
                shdr.Addr = DynInfo.Init;
                shdr.Offset = vaddr_to_foffset(shdr.Addr);
                shdr.Size = (ulong)initRetOffset;
                shdr.AddrAlign = 4;
                if (insert_shdr(shdrsStart, shdr, true) == ElfConstants.SHN_UNDEF)
                {
                    throw new Exception("failed to insert new shdr for .init");
                }
            }

            if (present_fini)
            {
                shdr = new Elf64Shdr();
                shdr.Name = shstrtab.GetOffset(".fini");
                shdr.Type = ElfConstants.SHT_PROGBITS;
                shdr.Flags = ElfConstants.SHF_ALLOC | ElfConstants.SHF_EXECINSTR;
                shdr.Addr = DynInfo.Fini;
                shdr.Offset = vaddr_to_foffset(shdr.Addr);
                shdr.Size = (ulong)finiBranchOffset;
                shdr.AddrAlign = 4;
                if (insert_shdr(shdrsStart, shdr, true) == ElfConstants.SHN_UNDEF)
                {
                    throw new Exception("failed to insert new shdr for .fini");
                }
            }

            var rodataPhdr = new Elf64Phdr(phdrsStart.Slice((int)NsoSegmentType.Rodata * Elf64Phdr.Length));
            shdr = new Elf64Shdr();
            shdr.Name = shstrtab.GetOffset(".dynstr");
            shdr.Type = ElfConstants.SHT_STRTAB;
            shdr.Flags = ElfConstants.SHF_ALLOC;
            shdr.Addr = Header.Segments[(int)NsoSegmentType.Rodata].MemoryOffset + Header.DynStr.Offset;
            shdr.Offset = rodataPhdr.Offset + Header.DynStr.Offset;
            shdr.Size = Header.DynStr.Size;
            shdr.AddrAlign = 1;
            uint dynstr_shndx = insert_shdr(shdrsStart, shdr);
            if (dynstr_shndx == ElfConstants.SHN_UNDEF)
            {
                throw new Exception("failed to insert new shdr for .dynstr");
            }

            uint last_local_dynsym_index = 0;
            IterateDynamic((sym, index) => {
                if (ELF64_ST_BIND(sym.Info) == ElfConstants.STB_LOCAL)
                {
                    last_local_dynsym_index = Math.Max(last_local_dynsym_index, index);
                }
            });
            shdr = new Elf64Shdr();
            shdr.Name = shstrtab.GetOffset(".dynsym");
            shdr.Type = ElfConstants.SHT_DYNSYM;
            shdr.Flags = ElfConstants.SHF_ALLOC;
            shdr.Addr = Header.Segments[(int)NsoSegmentType.Rodata].MemoryOffset + Header.DynSym.Offset;
            shdr.Offset = rodataPhdr.Offset + Header.DynSym.Offset;
            shdr.Size = Header.DynSym.Size;
            shdr.Link = dynstr_shndx;
            shdr.Info = last_local_dynsym_index + 1;
            shdr.AddrAlign = 8;
            shdr.EntSize = Elf64Sym.Length;
            uint dynsym_shndx = insert_shdr(shdrsStart, shdr);
            if (dynsym_shndx == ElfConstants.SHN_UNDEF)
            {
                throw new Exception("failed to insert new shdr for .dynsym");
            }

            var dyn_phdr = new Elf64Phdr(phdrsStart.Slice(((int)NsoSegmentType.Data + 1) * Elf64Phdr.Length));
            shdr = new Elf64Shdr();
            shdr.Name = shstrtab.GetOffset(".dynamic");
            shdr.Type = ElfConstants.SHT_DYNAMIC;
            shdr.Flags = ElfConstants.SHF_ALLOC | ElfConstants.SHF_WRITE;
            shdr.Addr = dyn_phdr.VAddr;
            shdr.Offset = dyn_phdr.Offset;
            shdr.Size = dyn_phdr.FileSize;
            shdr.Link = dynstr_shndx;
            shdr.AddrAlign = dyn_phdr.Align;
            shdr.EntSize = Elf64Dyn.Length;
            if (insert_shdr(shdrsStart, shdr) == ElfConstants.SHN_UNDEF)
            {
                throw new Exception("failed to insert new shdr for .dynamic");
            }

            shdr = new Elf64Shdr();
            shdr.Name = shstrtab.GetOffset(".rela.dyn");
            shdr.Type = ElfConstants.SHT_RELA;
            shdr.Flags = ElfConstants.SHF_ALLOC;
            shdr.Addr = DynInfo.Rela;
            shdr.Offset = vaddr_to_foffset(shdr.Addr);
            shdr.Size = DynInfo.RelaSize;
            shdr.Link = dynsym_shndx;
            shdr.AddrAlign = 8;
            shdr.EntSize = Elf64Rela.Length;
            if (insert_shdr(shdrsStart, shdr) == ElfConstants.SHN_UNDEF)
            {
                throw new Exception("failed to insert new shdr for .rela.dyn");
            }

            uint plt_shndx = ElfConstants.SHN_UNDEF;
            if (present_plt)
            {
                shdr = new Elf64Shdr();
                shdr.Name = shstrtab.GetOffset(".plt");
                shdr.Type = ElfConstants.SHT_PROGBITS;
                shdr.Flags = ElfConstants.SHF_ALLOC | ElfConstants.SHF_EXECINSTR;
                shdr.Addr = PltInfoAddr;
                shdr.Offset = vaddr_to_foffset(shdr.Addr);
                shdr.Size = PltInfoSize;
                shdr.AddrAlign = 0x10;
                shdr.EntSize = 0x10;
                plt_shndx = insert_shdr(shdrsStart, shdr, true);
                if (plt_shndx == ElfConstants.SHN_UNDEF)
                {
                    throw new Exception("failed to insert new shdr for .plt");
                }
            }

            if (present_got)
            {
                ulong glob_dat_end = (ulong)gotAddr;
                for (ulong i = 0; i < (DynInfo.RelaSize / Elf64Rela.Length); i++)
                {
                    var rela = new Elf64Rela(Image.AsSpan().Slice((int)(DynInfo.Rela + i * Elf64Rela.Length)));
                    if ((uint)(rela.Info) == ElfConstants.R_AARCH64_GLOB_DAT)
                    {
                        glob_dat_end = Math.Max(glob_dat_end, rela.Offset + 8);
                    }
                }
                shdr = new Elf64Shdr();
                shdr.Name = shstrtab.GetOffset(".got");
                shdr.Type = ElfConstants.SHT_PROGBITS;
                shdr.Flags = ElfConstants.SHF_ALLOC | ElfConstants.SHF_WRITE;
                shdr.Addr = (ulong)gotAddr;
                shdr.Offset = vaddr_to_foffset(shdr.Addr);
                shdr.Size = glob_dat_end - (ulong)gotAddr;
                shdr.AddrAlign = 8;
                shdr.EntSize = 8;
                if (insert_shdr(shdrsStart, shdr, true) == ElfConstants.SHN_UNDEF)
                {
                    throw new Exception("failed to insert new shdr for .got");
                }
            }

            if (present_got_plt)
            {
                shdr = new Elf64Shdr();
                shdr.Name = shstrtab.GetOffset(".got.plt");
                shdr.Type = ElfConstants.SHT_PROGBITS;
                shdr.Flags = ElfConstants.SHF_ALLOC | ElfConstants.SHF_WRITE;
                shdr.Addr = DynInfo.PltGot;
                shdr.Offset = vaddr_to_foffset(shdr.Addr);
                shdr.Size = (ulong)jumpSlotAddrEnd - DynInfo.PltGot;
                shdr.AddrAlign = 8;
                shdr.EntSize = 8;
                if (insert_shdr(shdrsStart, shdr, true) == ElfConstants.SHN_UNDEF)
                {
                    throw new Exception("failed to insert new shdr for .got.plt");
                }
            }

            if (present_rela_plt)
            {
                if (!present_plt)
                {
                    Console.Error.WriteLine("warning: .rela.plt with no .plt");
                }
                shdr = new Elf64Shdr();
                shdr.Name = shstrtab.GetOffset(".rela.plt");
                shdr.Type = ElfConstants.SHT_RELA;
                shdr.Flags = ElfConstants.SHF_ALLOC;
                if (plt_shndx != ElfConstants.SHN_UNDEF)
                {
                    shdr.Flags |= ElfConstants.SHF_INFO_LINK;
                }
                shdr.Addr = DynInfo.JumpRel;
                shdr.Offset = vaddr_to_foffset(shdr.Addr);
                shdr.Size = DynInfo.PltRelSize;
                shdr.Link = dynsym_shndx;
                shdr.Info = plt_shndx;
                shdr.AddrAlign = 8;
                shdr.EntSize = Elf64Rela.Length;
                if (insert_shdr(shdrsStart, shdr) == ElfConstants.SHN_UNDEF)
                {
                    throw new Exception("failed to insert new shdr for .rela.plt");
                }
            }

            if (present_init_array)
            {
                shdr = new Elf64Shdr();
                shdr.Name = shstrtab.GetOffset(".init_array");
                shdr.Type = ElfConstants.SHT_INIT_ARRAY;
                shdr.Flags = ElfConstants.SHF_ALLOC | ElfConstants.SHF_WRITE;
                shdr.Addr = DynInfo.InitArray;
                shdr.Offset = vaddr_to_foffset(shdr.Addr);
                shdr.Size = DynInfo.InitArraySize;
                shdr.AddrAlign = 8;
                if (insert_shdr(shdrsStart, shdr, true) == ElfConstants.SHN_UNDEF)
                {
                    throw new Exception("failed to insert new shdr for .init_array");
                }
            }

            if (present_fini_array)
            {
                shdr = new Elf64Shdr();
                shdr.Name = shstrtab.GetOffset(".fini_array");
                shdr.Type = ElfConstants.SHT_FINI_ARRAY;
                shdr.Flags = ElfConstants.SHF_ALLOC | ElfConstants.SHF_WRITE;
                shdr.Addr = DynInfo.FiniArray;
                shdr.Offset = vaddr_to_foffset(shdr.Addr);
                shdr.Size = DynInfo.FiniArraySize;
                shdr.AddrAlign = 8;
                if (insert_shdr(shdrsStart, shdr, true) == ElfConstants.SHN_UNDEF)
                {
                    throw new Exception("failed to insert new shdr for .fini_array");
                }
            }

            if (present_hash)
            {
                var hash = new DynInfoHash(Image.AsSpan().Slice((int)DynInfo.Hash));
                shdr = new Elf64Shdr();
                shdr.Name = shstrtab.GetOffset(".hash");
                shdr.Type = ElfConstants.SHT_HASH;
                shdr.Flags = ElfConstants.SHF_ALLOC;
                shdr.Addr = DynInfo.Hash;
                shdr.Offset = vaddr_to_foffset(shdr.Addr);
                shdr.Size = (ulong)(DynInfoHash.Length + hash.Bucket * 4 + hash.Chain * 4);
                shdr.Link = dynsym_shndx;
                shdr.AddrAlign = 8;
                shdr.EntSize = 4;
                if (insert_shdr(shdrsStart, shdr) == ElfConstants.SHN_UNDEF)
                {
                    throw new Exception("failed to insert new shdr for .hash");
                }
            }

            if (present_gnu_hash)
            {
                var gnu_hash = new GnuHash(Image.AsSpan().Slice((int)DynInfo.GnuHash));
                uint gnu_hash_len = GnuHash.Length;
                gnu_hash_len += gnu_hash.MaskWords * 8;
                gnu_hash_len += gnu_hash.BucketCount * 4;
                ulong dynsymcount = Header.DynSym.Size / Elf64Sym.Length;
                gnu_hash_len += (uint)((dynsymcount - gnu_hash.SymIndex) * 4);
                shdr = new Elf64Shdr();
                shdr.Name = shstrtab.GetOffset(".gnu.hash");
                shdr.Type = ElfConstants.SHT_GNU_HASH;
                shdr.Flags = ElfConstants.SHF_ALLOC;
                shdr.Addr = DynInfo.GnuHash;
                shdr.Offset = vaddr_to_foffset(shdr.Addr);
                shdr.Size = gnu_hash_len;
                shdr.Link = dynsym_shndx;
                shdr.AddrAlign = 8;
                shdr.EntSize = 4;
                if (insert_shdr(shdrsStart, shdr) == ElfConstants.SHN_UNDEF)
                {
                    throw new Exception("failed to insert new shdr for .gnu.hash");
                }
            }

            if (present_note)
            {
                shdr = new Elf64Shdr();
                shdr.Name = shstrtab.GetOffset(".note");
                shdr.Type = ElfConstants.SHT_NOTE;
                shdr.Flags = ElfConstants.SHF_ALLOC;
                shdr.Addr = (ulong)NoteOffset;
                shdr.Offset = vaddr_to_foffset(shdr.Addr);
                shdr.Size = Elf64Nhdr.Length + Note.Value.DescriptorSize + Note.Value.NameSize;
                shdr.AddrAlign = 4;
                if (insert_shdr(shdrsStart, shdr) == ElfConstants.SHN_UNDEF)
                {
                    throw new Exception("failed to insert new shdr for .note");
                }
            }

            if (present_eh)
            {
                shdr = new Elf64Shdr();
                shdr.Name = shstrtab.GetOffset(".eh_frame_hdr");
                shdr.Type = ElfConstants.SHT_PROGBITS;
                shdr.Flags = ElfConstants.SHF_ALLOC;
                shdr.Addr = (ulong)EhInfoHdrAddr;
                shdr.Offset = vaddr_to_foffset(shdr.Addr);
                shdr.Size = (ulong)ehInfoHdrSize;
                shdr.AddrAlign = 4;
                if (insert_shdr(shdrsStart, shdr, true) == ElfConstants.SHN_UNDEF)
                {
                    throw new Exception("failed to insert new shdr for .eh_frame_hdr");
                }
                shdr = new Elf64Shdr();
                shdr.Name = shstrtab.GetOffset(".eh_frame");
                shdr.Type = ElfConstants.SHT_PROGBITS;
                shdr.Flags = ElfConstants.SHF_ALLOC;
                shdr.Addr = ehInfoFrameAddr;
                shdr.Offset = vaddr_to_foffset(shdr.Addr);
                shdr.Size = ehInfoFrameSize;
                shdr.AddrAlign = 4;
                if (insert_shdr(shdrsStart, shdr, true) == ElfConstants.SHN_UNDEF)
                {
                    throw new Exception("failed to insert new shdr for .eh_frame");
                }
            }

            shdr = new Elf64Shdr();
            shdr.Name = shstrtab.GetOffset(".shstrtab");
            shdr.Type = ElfConstants.SHT_STRTAB;
            shdr.Offset = (ulong)shstrtab.Offset;
            shdr.Size = (ulong)shstrtab.Buffer.Length;
            shdr.AddrAlign = 1;
            ehdr.SHStrNdx = (ushort)insert_shdr(shdrsStart, shdr);
            if (ehdr.SHStrNdx == ElfConstants.SHN_UNDEF)
            {
                throw new Exception("failed to insert new shdr for .shstrtab");
            }

            ehdr.Write(elf);
            return elf;
        }

        private static int MemoryCompareWithMask(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, ReadOnlySpan<byte> mask, int length)
        {
            var x = 0;
            while (length-- > 0 && x == 0)
            {
                x = (a[0] ^ b[0]) & mask[0];
                a = a.Slice(1);
                b = b.Slice(1);
                mask = mask.Slice(1);
            }
            return x;
        }

        private static int MemoryCompare(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, int length)
        {
            var x = 0;
            while (length-- > 0 && x == 0)
            {
                x = (a[0] ^ b[0]);
                a = a.Slice(1);
                b = b.Slice(1);
            }
            return x;
        }

        private static int MemoryLocateWithMask(ReadOnlySpan<byte> haystack, int haystackLength, ReadOnlySpan<byte> needle, ReadOnlySpan<byte> mask, int needleLength)
        {
            var currentOffset = 0;
            var maxOffset = haystackLength - needleLength;
            while (currentOffset <= maxOffset)
            {
                var p = haystack.Slice(currentOffset);
                if (MemoryCompareWithMask(p, needle, mask, needleLength) == 0)
                {
                    return currentOffset;
                }
                currentOffset += 1;
            }
            return -1;
        }

        private static int MemoryLocate(ReadOnlySpan<byte> haystack, int haystackLength, ReadOnlySpan<byte> needle, int needleLength)
        {
            var currentOffset = 0;
            var maxOffset = haystackLength - needleLength;
            while (currentOffset <= maxOffset)
            {
                var p = haystack.Slice(currentOffset);
                if (MemoryCompare(p, needle, needleLength) == 0)
                {
                    return currentOffset;
                }
                currentOffset += 1;
            }
            return -1;
        }

        private static int MemoryLocateReverse(ReadOnlySpan<byte> haystack, int haystackLength, ReadOnlySpan<byte> needle, int needleLength)
        {
            var currentOffset = haystackLength - needleLength;
            var minOffset = 0;
            while (currentOffset >= minOffset)
            {
                var p = haystack.Slice(currentOffset);
                if (MemoryCompare(p, needle, needleLength) == 0)
                {
                    return currentOffset;
                }
                currentOffset -= 1;
            }
            return -1;
        }

        private static int ELF64_ST_BIND(int info) => ((info) >> 4);

        private static long ALIGN_DOWN(long x, long align) => ((x) & ~((align) - 1));
        private static int ALIGN_DOWN(int x, int align) => ((x) & ~((align) - 1));
        private static long ALIGN_UP(long x, long align) => ALIGN_DOWN((x) + ((align) - 1), (align));
        private static int ALIGN_UP(int x, int align) => ALIGN_DOWN((x) + ((align) - 1), (align));

        private class StringTable
        {
            public StringTable()
            {
                entries = new Dictionary<string, uint>();
                AddString("");
            }

            private readonly Dictionary<string, uint> entries;

            public byte[] Buffer { get; private set; }
            public int Size { get; private set; }
            public int Offset { get; set; }

            private uint Watermark { get; set; }

            public void AddString(string str)
            {
                if (!entries.ContainsKey(str))
                {
                    entries[str] = Watermark;
                    Watermark += (uint)(str.Length + 1); // 1 is the null char
                }
            }

            public uint GetOffset(string name)
            {
                if (entries.TryGetValue(name, out var value))
                {
                    return value;
                }
                return 0;
            }

            public byte[] GetBuffer()
            {
                var data = new byte[Watermark];
                foreach (var entry in entries)
                {
                    Encoding.ASCII.GetBytes(entry.Key).CopyTo(data, entry.Value);
                }
                return data;
            }

            public void Build()
            {
                Buffer = GetBuffer();
                Size = ALIGN_UP(Buffer.Length, 0x10);
            }
        }

        private struct ModPointer
        {
            public ModPointer(ReadOnlySpan<byte> data)
            {
                Field0 = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(0, 4));
                MaskOffset = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(4, 4));
            }

            public uint Field0 { get; }
            public uint MaskOffset { get; }
        }

        private struct ModHeader
        {
            public ModHeader(ReadOnlySpan<byte> data)
            {
                Magic = data.Slice(0, 4).ToArray();
                DynamicOffset = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(4, 4));
                BssStartOffset = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(8, 4));
                BssEndOffset = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(12, 4));
                EhStartOffset = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(16, 4));
                EhEndOffset = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(20, 4));
                ModuleObjectOffset = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(24, 4));
            }

            // yaya, there are some fields here...for parsing, easier to ignore.
            //ModPointer mod_ptr;
            public byte[] Magic { get; }
            public int DynamicOffset { get; }
            public int BssStartOffset { get; }
            public int BssEndOffset { get; }
            public int EhStartOffset { get; }
            public int EhEndOffset { get; }
            public int ModuleObjectOffset { get; }
            // It seems the area around MOD0 is used for .note section
            // There is also a nss-name section
        };

        private class DynInfoData
        {
            public ulong SymTab { get; set; }
            public ulong Rela { get; set; }
            public ulong RelaSize { get; set; }
            public ulong JumpRel { get; set; }
            public ulong PltRelSize { get; set; }
            public ulong StrTab { get; set; }
            public ulong StrSize { get; set; }
            public ulong PltGot { get; set; }
            public ulong Hash { get; set; }
            public ulong GnuHash { get; set; }
            public ulong Init { get; set; }
            public ulong Fini { get; set; }
            public ulong InitArray { get; set; }
            public ulong InitArraySize { get; set; }
            public ulong FiniArray { get; set; }
            public ulong FiniArraySize { get; set; }
        }

        private struct DynInfoHash
        {
            public const int Length = 8;

            public DynInfoHash(ReadOnlySpan<byte> data)
            {
                Bucket = BinaryPrimitives.ReadInt32LittleEndian(data);
                Chain = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(4));
            }
            public int Bucket { get; set; }
            public int Chain { get; set; }
        }

        private struct GnuHash
        {
            public const int Length = 16;

            public GnuHash(ReadOnlySpan<byte> data)
            {
                BucketCount = BinaryPrimitives.ReadUInt32LittleEndian(data);
                SymIndex = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(4));
                MaskWords = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(8));
                Shift2 = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(12));
            }

            public uint BucketCount { get; set; }
            public uint SymIndex { get; set; }
            public uint MaskWords { get; set; }
            public uint Shift2 { get; set; }
        }
    }
}
