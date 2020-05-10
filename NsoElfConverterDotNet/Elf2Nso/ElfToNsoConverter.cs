using K4os.Compression.LZ4;
using NsoElfConverterDotNet.Structures;
using NsoElfConverterDotNet.Structures.Elf;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace NsoElfConverterDotNet.Elf2Nso
{
    internal static class ElfToNsoConverter
    {
        public static byte[] ConvertElfToNso(ReadOnlySpan<byte> elf)
        {
            if (elf.Length < Elf64Ehdr.Length)
            {
                throw new ArgumentException("Length of ELF data is less than the ELF header", nameof(elf));
            }

            var header = new Elf64Ehdr(elf);
            if (header.Machine != ElfConstants.EM_AARCH64)
            {
                throw new ArgumentException("ELF data must have machine of AArch64", nameof(elf));
            }

            var phEnd = header.PhOff + (ulong)header.PHNum * Elf64Phdr.Length;
            if (phEnd < header.PhOff || phEnd > (ulong)elf.Length)
            {
                throw new ArgumentException("Physical header address outside of file", nameof(elf));
            }

            using var sha256 = SHA256.Create();

            var nsoHeader = new NsoHeader();
            var compressedBuffers = new List<byte[]>(3);
            uint fileOffset = NsoHeader.Length;
            int j = 0;
            for (int i = 0; i < 3; i++)
            {
                Elf64Phdr phdr = null;
                while (j < header.PHNum)
                {
                    var phOffset = (long)header.PhOff + j++ * Elf64Phdr.Length;
                    var current = new Elf64Phdr(elf.Slice((int)phOffset, header.PHEntSize));
                    if (current.Type == ElfConstants.PT_LOAD)
                    {
                        phdr = current;
                        break;
                    }
                }

                if (phdr == null)
                {
                    throw new ArgumentException("Invalid ELF: expected 3 loadable phdrs", nameof(elf));
                }

                nsoHeader.Segments[i].FileOffset = fileOffset;
                nsoHeader.Segments[i].MemoryOffset = (uint)phdr.VAddr;
                nsoHeader.Segments[i].MemorySize = (uint)phdr.FileSize;

                // for .data segment this field contains bss size
                if (i == 2)
                {
                    nsoHeader.Segments[i].AlignOrTotalSz = (uint)(phdr.MemSize - phdr.FileSize);
                }
                else
                {
                    nsoHeader.Segments[i].AlignOrTotalSz = 1;
                }

                var sectionData = elf.Slice((int)phdr.Offset, (int)phdr.FileSize);
                nsoHeader.Hashes[i] = sha256.ComputeHash(sectionData.ToArray());

                var compressedBuffer = new byte[LZ4Codec.MaximumOutputSize(sectionData.Length)];
                var compressedLength = LZ4Codec.Encode(sectionData, compressedBuffer, LZ4Level.L00_FAST);
                compressedBuffers.Add(compressedBuffer);
                nsoHeader.SegmentFileSIzes[i] = (uint)compressedLength;
                fileOffset += (uint)compressedLength;
            }

            // Iterate over sections to find build id.
            var currentSectionHeaderOffset = header.ShOff;
            for (int i = 0; i < header.SHNum; i++)
            {
                var currentShHeader = new Elf64Shdr(elf.Slice((int)currentSectionHeaderOffset, header.SHEntSize));
                if (currentShHeader.Type == ElfConstants.SHT_NOTE)
                {
                    var noteData = elf.Slice((int)currentShHeader.Offset, Elf64Nhdr.Length);
                    var noteHeader = new Elf64Nhdr(noteData);
                    var noteName = elf.Slice((int)currentShHeader.Offset + Elf64Nhdr.Length, (int)noteHeader.NameSize);
                    var noteDesc = elf.Slice((int)currentShHeader.Offset + Elf64Nhdr.Length + (int)noteHeader.NameSize, (int)noteHeader.DescriptorSize);
                    var noteNameString = Encoding.ASCII.GetString(noteName.Slice(0, 4));
                    if (noteHeader.Type == ElfConstants.NT_GNU_BUILD_ID && noteHeader.NameSize == 4 && noteNameString == "GNU\0")
                    {
                        var buildIdSize = noteHeader.DescriptorSize;
                        if (buildIdSize > 0x20)
                        {
                            buildIdSize = 0x20;
                        }
                        noteDesc.Slice(0, (int)buildIdSize).CopyTo(nsoHeader.BuildId);
                    }
                }
                currentSectionHeaderOffset += header.SHEntSize;
            }

            var headerData = nsoHeader.ToByteArray();
            var buffer = new List<byte>(headerData.Length + nsoHeader.SegmentFileSIzes.Cast<int>().Sum());
            buffer.AddRange(headerData);
            for (int i = 0; i < nsoHeader.SegmentFileSIzes.Length; i++)
            {
                buffer.AddRange(compressedBuffers[i].Take((int)nsoHeader.SegmentFileSIzes[i]));
            }
            return buffer.ToArray();
        }
    }
}
