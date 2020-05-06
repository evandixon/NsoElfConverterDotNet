using K4os.Compression.LZ4;
using NsoElfConverterDotNet.Elf2Nso;
using NsoElfConverterDotNet.Structures;
using SkyEditor.IO.Binary;
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Reflection.Emit;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;

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
            var offset = mod.dynamic_offset;
            var dynamic = new Elf64Dyn(modBase.Slice(offset));
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
                dynamic = new Elf64Dyn(modBase.Slice(offset + dynamicIndex * Elf64Dyn.Length));
            }
        }

        public NsoFile(byte[] nso) : this(new BinaryFile(nso))
        {
        }

        public NsoHeader Header { get; }

        private byte[] Image { get; }
        private DynInfoData DynInfo { get; }

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

            throw new NotImplementedException();
        }

        private class StringTable
        {
            public void AddString(string str)
            {
                throw new NotImplementedException();
            }

            public uint GetOffset(string name)
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
