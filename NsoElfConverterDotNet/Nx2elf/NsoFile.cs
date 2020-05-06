using K4os.Compression.LZ4;
using NsoElfConverterDotNet.Elf2Nso;
using NsoElfConverterDotNet.Structures;
using NsoElfConverterDotNet.Structures.Elf;
using SkyEditor.IO.Binary;
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Reflection.Emit;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace NsoElfConverterDotNet.Nx2elf
{
    public class NsoFile
    {
        public NsoFile(IReadOnlyBinaryDataAccessor accessor)
        {
            if (accessor.Length < NsoHeader.Length)
            {
                throw new ArgumentException("NSO data is smaller than the header", nameof(accessor));
            }

            Header = new NsoHeader(accessor.Slice(0, NsoHeader.Length));

            // assume segments are after each other and mem offsets are aligned
            // note: there are also symbols "_start" and "end" which describe
            // the total size.
            var dataSegment = Header.Segments[(int)NsoSegmentType.Data];
            var imageSize = dataSegment.MemoryOffset + dataSegment.MemorySize + dataSegment.AlignOrTotalSz;
            Image = new byte[imageSize];

            for (int i = 0; i < 3; i++)
            {
                var segment = Header.Segments[i];
                var fileSize = Header.SegmentFileSIzes[i];

                var compressed = accessor.ReadSpan(segment.FileOffset, (int)fileSize);
                var decompressed = Image.AsSpan().Slice((int)segment.MemoryOffset, (int)segment.MemorySize);
                var decompressedSize = LZ4Codec.Decode(compressed, decompressed);
                if (decompressedSize <= 0)
                {
                    throw new Exception($"Failed to decompressed segment {i}.");
                }
            }

            var modPtr = new ModPointer(Image);
            var modBase = Image.AsSpan().Slice((int)modPtr.magic_offset);
            var mod = new ModHeader(modBase);

            DynInfo = new DynInfoData();
            DynOffset = mod.dynamic_offset;
            var dynamic = new Elf64Dyn(modBase.Slice(DynOffset));
            var dynamicIndex = 0;
            while (dynamic.Tag != default)
            {
                switch (dynamic.Tag)
                {
                    case ElfConstants.DT_SYMTAB:
                        DynInfo.symtab = dynamic.Un;
                        break;
                    case ElfConstants.DT_RELA:
                        DynInfo.rela = dynamic.Un;
                        break;
                    case ElfConstants.DT_RELASZ:
                        DynInfo.relasz = dynamic.Un;
                        break;
                    case ElfConstants.DT_JMPREL:
                        DynInfo.jmprel = dynamic.Un;
                        break;
                    case ElfConstants.DT_PLTRELSZ:
                        DynInfo.pltrelsz = dynamic.Un;
                        break;
                    case ElfConstants.DT_STRTAB:
                        DynInfo.strtab = dynamic.Un;
                        break;
                    case ElfConstants.DT_STRSZ:
                        DynInfo.strsz = dynamic.Un;
                        break;
                    case ElfConstants.DT_PLTGOT:
                        DynInfo.pltgot = dynamic.Un;
                        break;
                    case ElfConstants.DT_HASH:
                        DynInfo.hash = dynamic.Un;
                        break;
                    case ElfConstants.DT_GNU_HASH:
                        DynInfo.gnu_hash = dynamic.Un;
                        break;
                    case ElfConstants.DT_INIT:
                        DynInfo.init = dynamic.Un;
                        break;
                    case ElfConstants.DT_FINI:
                        DynInfo.fini = dynamic.Un;
                        break;
                    case ElfConstants.DT_INIT_ARRAY:
                        DynInfo.init_array = dynamic.Un;
                        break;
                    case ElfConstants.DT_INIT_ARRAYSZ:
                        DynInfo.init_arraysz = dynamic.Un;
                        break;
                    case ElfConstants.DT_FINI_ARRAY:
                        DynInfo.fini_array = dynamic.Un;
                        break;
                    case ElfConstants.DT_FINI_ARRAYSZ:
                        DynInfo.fini_arraysz = dynamic.Un;
                        break;
                }

                dynamicIndex += 1;
                dynamic = new Elf64Dyn(modBase.Slice(DynOffset + dynamicIndex * Elf64Dyn.Length));
            }

            // Resolve Plt
            var textSegment = Header.Segments[(int)NsoSegmentType.Text];
            var textSegmentData = Image.AsSpan().Slice((int)textSegment.MemoryOffset, (int)textSegment.MemorySize);
            if (DynInfo.pltrelsz != default)
            {
                var pltPattern = new byte[]
                {
                    0xf0, 0x7b, 0xbf, 0xa9,
                    0xd0, 0x04, 0x00, 0xd0,
                    0x11, 0x8a, 0x42, 0xf9,
                    0x10, 0x42, 0x14, 0x91,

                    0x20, 0x02, 0x1f, 0xd6,
                    0x1f, 0x20, 0x32, 0x50,
                    0x1f, 0x20, 0x32, 0x50,
                    0x1f, 0x20, 0x32, 0x50
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
                var found = memmem_m(textSegmentData, textSegmentData.Length, pltPattern, pltMask, pltPattern.Length);
                if (found != 0)
                {
                    PltInfoAddr = (ulong)found;
                    // Assume the plt exactly matches .rela.plt
                    var pltEntryCount = DynInfo.pltrelsz / Elf64Rela.Length;
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
            foreach (var segment in Header.Segments)
            {
                var segmentData = Image.AsSpan().Slice((int)segment.MemoryOffset, (int)segment.MemorySize);
                var noteOffset = memmemr(segmentData, segmentData.Length, md5BuildIdNeedle, md5BuildIdNeedle.Length);
                if (noteOffset == 0)
                {
                    noteOffset = memmemr(segmentData, segmentData.Length, sha1BuildIdNeedle, sha1BuildIdNeedle.Length);
                }

                if (noteOffset != 0)
                {
                    Note = new Elf64Nhdr(Image.AsSpan().Slice(noteOffset));
                }
            }

            int mod_get_offset(ReadOnlySpan<byte> modBase, int relative_offset) {
                var ptr = modBase.Slice(relative_offset);
                return BinaryPrimitives.ReadInt32LittleEndian(ptr);
            };

            EhInfoHdrAddr = mod_get_offset(modBase, (int)mod.eh_start_offset);
            EhInfoHdrSize = mod_get_offset(modBase, (int)mod.eh_end_offset) - EhInfoHdrAddr;
        }

        public NsoFile(byte[] nso) : this(new BinaryFile(nso))
        {
        }

        public NsoHeader Header { get; }

        private byte[] Image { get; }
        private DynInfoData DynInfo { get; }
        private int DynOffset { get; }
        private Elf64Nhdr? Note { get; }
        private ulong PltInfoAddr { get; }
        private ulong PltInfoSize { get; }
        private int EhInfoHdrAddr { get; }
        private int EhInfoHdrSize { get; }

        private void IterateDynamic(Action<Elf64Sym, uint> action)
        {
            for (uint i = 0; i < Header.dynsym.Size / Elf64Sym.Length; i++)
            {
                var sym = new Elf64Sym(Image.AsSpan().Slice((int)DynInfo.symtab));
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

            IterateDynamic((sym, _) =>
            {
                if (sym.Shndx >= ElfConstants.SHN_LORESERVE)
                {
                    return;
                }

                numShdrs = (ushort)Math.Max(numShdrs, sym.Value);
                if (sym.Shndx != ElfConstants.SHT_NULL && knownSections.Count(kv => kv.Key == sym.Shndx) != 0)
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
                    for (ushort i = 0; i < ElfConstants.SHN_LORESERVE; i++)
                    {
                        if (!knownSections.ContainsKey(i))
                        {
                            return i;
                        }
                    }
                    return ElfConstants.SHN_UNDEF;
                }

                var shndx = nextFree(ElfConstants.SHN_UNDEF);
                if (shndx != ElfConstants.SHN_UNDEF && shstrtab.GetOffset(".text") != 0 && Header.Segments[(int)NsoSegmentType.Text].MemoryOffset > 0)
                {
                    knownSections[shndx] = vaddrToShdr(Header.Segments[(int)NsoSegmentType.Text].MemoryOffset);
                    shndx = nextFree(shndx);
                }
                if (shndx != ElfConstants.SHN_UNDEF && shstrtab.GetOffset(".rodata") != 0 && Header.Segments[(int)NsoSegmentType.Rodata].MemoryOffset > 0)
                {
                    knownSections[shndx] = vaddrToShdr(Header.Segments[(int)NsoSegmentType.Rodata].MemoryOffset);
                    shndx = nextFree(shndx);
                }
                if (shndx != ElfConstants.SHN_UNDEF && shstrtab.GetOffset(".data") != 0 && Header.Segments[(int)NsoSegmentType.Data].MemoryOffset > 0)
                {
                    knownSections[shndx] = vaddrToShdr(Header.Segments[(int)NsoSegmentType.Data].MemoryOffset);
                    shndx = nextFree(shndx);
                }
                if (shndx != ElfConstants.SHN_UNDEF && shstrtab.GetOffset(".bss") != 0 && Header.Segments[(int)NsoSegmentType.Data].AlignOrTotalSz > 0)
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
            if (DynInfo.jmprel != 0)
            {
                for (ulong i = 0; i < DynInfo.pltrelsz / Elf64Rela.Length; i++)
                {
                    var rela = new Elf64Rela(Image.AsSpan().Slice((int)(DynInfo.jmprel + i * Elf64Rela.Length)));
                    if (rela.Info == ElfConstants.R_AARCH64_JUMP_SLOT)
                    {
                        jumpSlotAddrEnd = Math.Max(jumpSlotAddrEnd, (int)(rela.Offset + 8));
                    }
                }
            }
            ALLOC_SHDR_IF(jumpSlotAddrEnd != 0 && DynInfo.pltgot != 0, ref present_got_plt);

            var gotAddr = 0;
            if (jumpSlotAddrEnd != 0)
            {
                var gotDynamicPtr = BitConverter.GetBytes((ulong)DynOffset);
                var found = memmem(Image.AsSpan().Slice(jumpSlotAddrEnd), Image.Length - jumpSlotAddrEnd, gotDynamicPtr, gotDynamicPtr.Length);
                if (found != 0)
                {
                    gotAddr = found;
                }
            }

            ALLOC_SHDR_IF(gotAddr != 0 && DynInfo.rela != 0, ref present_got);
            ALLOC_SHDR_IF(present_got_plt && DynInfo.jmprel != 0 && DynInfo.pltrelsz != 0, ref present_rela_plt);
            ALLOC_SHDR_IF(DynInfo.hash != 0, ref present_hash);
            ALLOC_SHDR_IF(DynInfo.gnu_hash != 0, ref present_gnu_hash);
            ALLOC_SHDR_IF(DynInfo.init_array != 0 && DynInfo.init_arraysz != 0, ref present_init_array);
            ALLOC_SHDR_IF(DynInfo.fini_array != 0 && DynInfo.fini_arraysz != 0, ref present_fini_array);
            ALLOC_SHDR_IF(Note.HasValue, ref present_note);

            var initRetOffset = 0;
            if (DynInfo.init != 0)
            {
                var initPtr = Image.AsSpan().Slice((int)DynInfo.init);
                for (int i = 0; /* no max */ ; i++)
                {
                    if (BinaryPrimitives.ReadUInt32LittleEndian(initPtr.Slice(i)) == 0xd65f03c0ul)
                    {
                        initRetOffset = (i + 1) * 4;
                        break;
                    }
                }
                ALLOC_SHDR_IF(initRetOffset != 0, ref present_init);
            }

            var finiBranchOffset = 0;
            if (DynInfo.fini != 0)
            {
                var finiPtr = Image.AsSpan().Slice((int)DynInfo.fini);
                for (int i = 0; i < 0x20; i++)
                {
                    if ((BinaryPrimitives.ReadUInt32LittleEndian(finiPtr.Slice(i)) & 0xff000000ul) == 0x14000000ul)
                    {
                        finiBranchOffset = (i + 1) * 4;
                        break;
                    }
                }
                ALLOC_SHDR_IF(finiBranchOffset != 0, ref present_fini);
            }

            uint ehInfoFrameAddr;
            uint ehInfoFrameSize;
            uint ehInfoHdrAddr;
            uint ehInfoHdrSize;

            uint ehFramePtr;
            if (ElfEHInfo.MeasureFrame(Image, EhInfoHdrAddr, out ehFramePtr, out ehInfoFrameSize))
            {
                ehInfoFrameAddr = (uint)(EhInfoHdrAddr + ehFramePtr);
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
            ehdr.EhSize = Elf64Dyn.Length;
            ehdr.Flags = 0;
            ehdr.Entry = Header.Segments[(int)NsoSegmentType.Text].MemoryOffset;
            ehdr.PhOff = ehdr.EhSize;
            ehdr.PHEntSize = Elf64Phdr.Length;
            ehdr.PHNum = (ushort)numPhdrs;
            ehdr.ShOff = ehdr.PhOff + ehdr.PHEntSize + ehdr.PHNum;
            ehdr.SHEntSize = Elf64Shdr.Length;
            ehdr.SHNum = numShdrs;
            ehdr.SHStrNdx = ElfConstants.SHN_UNDEF;
            ehdr.Write(elf);

            // IDA only _needs_ phdrs and dynamic phdr to give good results

            throw new NotImplementedException();

            return elf;
        }

        private static int memcmp_m(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, ReadOnlySpan<byte> mask, int length)
        {
            var x = 0;
            while (length-- > 0 && x == 0)
            {
                x = (a[0] & b[0]) & mask[0];
                a = a.Slice(1);
                b = b.Slice(1);
                mask = mask.Slice(1);
            }
            return x;
        }

        private static int memcmp(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, int length)
        {
            var x = 0;
            while (length-- > 0 && x == 0)
            {
                x = (a[0] & b[0]);
                a = a.Slice(1);
                b = b.Slice(1);
            }
            return x;
        }

        private static int memmem_m(ReadOnlySpan<byte> haystack, int haystackLength, ReadOnlySpan<byte> needle, ReadOnlySpan<byte> mask, int needleLength)
        {
            var p = haystack;
            var currentOffset = 0;
            var maxOffset = haystackLength - needleLength;
            while (currentOffset < maxOffset)
            {
                if (memcmp_m(p, needle, mask, needleLength) == 0)
                {
                    return currentOffset;
                }
                currentOffset += 1;
                p = p.Slice(1);
            }
            return 0;
        }

        private static int memmem(ReadOnlySpan<byte> haystack, int haystackLength, ReadOnlySpan<byte> needle, int needleLength)
        {
            var p = haystack;
            var currentOffset = 0;
            var maxOffset = haystackLength - needleLength;
            while (currentOffset < maxOffset)
            {
                if (memcmp(p, needle, needleLength) == 0)
                {
                    return currentOffset;
                }
                currentOffset += 1;
                p = p.Slice(1);
            }
            return 0;
        }

        private static int memmemr(ReadOnlySpan<byte> haystack, int haystackLength, ReadOnlySpan<byte> needle, int needleLength)
        {
            var currentOffset = haystackLength - needleLength;
            var p = haystack.Slice(currentOffset);
            var minOffset = 0;
            while (currentOffset >= minOffset)
            {
                if (memcmp(p, needle, needleLength) == 0)
                {
                    return currentOffset;
                }
                currentOffset -= 1;
                p = haystack.Slice(currentOffset);
            }
            return 0;
        }

        private static long ALIGN_DOWN(long x, long align) => ((x) & ~((align) - 1));
        private static long ALIGN_UP(long x, long align) => ALIGN_DOWN((x) + ((align) - 1), (align));

        private class StringTable
        {
            public StringTable()
            {
                entries = new Dictionary<string, uint>();
                AddString("");
            }

            private readonly Dictionary<string, uint> entries;

            public byte[] Buffer { get; private set; }
            public int Size { get => Buffer.Length; }

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
                return entries.GetValueOrDefault(name);
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
                throw new NotImplementedException();
            }
        }

        private struct ModPointer
        {
            public ModPointer(ReadOnlySpan<byte> data)
            {
                field_0 = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(0, 4));
                magic_offset = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(4, 4));
            }

            public uint field_0 { get; }
            public uint magic_offset { get; }
        }

        private struct ModHeader
        {
            public ModHeader(ReadOnlySpan<byte> data)
            {
                magic = data.Slice(0, 4).ToArray();
                dynamic_offset = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(4, 4));
                bss_start_offset = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(8, 4));
                bss_end_offset = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(12, 4));
                eh_start_offset = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(16, 4));
                eh_end_offset = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(20, 4));
                module_object_offset = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(24, 4));
            }

            // yaya, there are some fields here...for parsing, easier to ignore.
            //ModPointer mod_ptr;
            public byte[] magic { get; }
            public int dynamic_offset { get; }
            public int bss_start_offset { get; }
            public int bss_end_offset { get; }
            public int eh_start_offset { get; }
            public int eh_end_offset { get; }
            public int module_object_offset { get; }
            // It seems the area around MOD0 is used for .note section
            // There is also a nss-name section
        };

        private class DynInfoData
        {
            public ulong symtab { get; set; }
            public ulong rela { get; set; }
            public ulong relasz { get; set; }
            public ulong jmprel { get; set; }
            public ulong pltrelsz { get; set; }
            public ulong strtab { get; set; }
            public ulong strsz { get; set; }
            public ulong pltgot { get; set; }
            public ulong hash { get; set; }
            public ulong gnu_hash { get; set; }
            public ulong init { get; set; }
            public ulong fini { get; set; }
            public ulong init_array { get; set; }
            public ulong init_arraysz { get; set; }
            public ulong fini_array { get; set; }
            public ulong fini_arraysz { get; set; }
        }
    }
}
