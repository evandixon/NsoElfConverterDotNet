using K4os.Compression.LZ4;
using SkyEditor.IO.Binary;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace NsoElfConverterDotNet.Elf2Nso
{
    internal static class ElfToNsoConverter
    {
        public static byte[] ConvertElfToNso(IReadOnlyBinaryDataAccessor elf)
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
                    var current = new Elf64Phdr(elf.Slice(phOffset, header.PHEntSize));
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

                nsoHeader.Segments[i].FileOff = fileOffset;
                nsoHeader.Segments[i].DstOff = (uint)phdr.VAddr;
                nsoHeader.Segments[i].DecompSz = (uint)phdr.FileSize;

                // for .data segment this field contains bss size
                if (i == 2)
                {
                    nsoHeader.Segments[i].AlignOrTotalSz = (uint)(phdr.MemSize - phdr.FileSize);
                }
                else
                {
                    nsoHeader.Segments[i].AlignOrTotalSz = 1;
                }

                var sectionData = elf.ReadSpan((long)phdr.Offset, (int)phdr.FileSize);
                nsoHeader.Hashes[i] = sha256.ComputeHash(sectionData.ToArray());

                var compressedBuffer = new byte[LZ4Codec.MaximumOutputSize(sectionData.Length)];
                var compressedLength = LZ4Codec.Encode(sectionData, compressedBuffer, LZ4Level.L00_FAST);
                compressedBuffers.Add(compressedBuffer);
                nsoHeader.CompSz[i] = (uint)compressedLength;
                fileOffset += (uint)compressedLength;
            }

            // Iterate over sections to find build id.
            var currentSectionHeaderOffset = header.ShOff;
            for (int i = 0; i < header.SHNum; i++)
            {
                var currentShHeader = new Elf64Shdr(elf.Slice((long)currentSectionHeaderOffset, header.SHEntSize));
                if (currentShHeader.Type == ElfConstants.SHT_NOTE)
                {
                    var noteData = elf.Slice((long)currentShHeader.Offset, ElfNote.Length);
                    var noteHeader = new ElfNote(noteData);
                    var noteName = elf.Slice((long)currentShHeader.Offset + ElfNote.Length, noteHeader.NameSize);
                    var noteDesc = elf.Slice((long)currentShHeader.Offset + ElfNote.Length + noteHeader.NameSize, noteHeader.DescriptorSize);
                    var noteNameString = noteName.ReadString(0, 4, Encoding.ASCII);
                    if (noteHeader.Type == ElfConstants.NT_GNU_BUILD_ID && noteHeader.NameSize == 4 && noteNameString == "GNU\0")
                    {
                        var buildIdSize = noteHeader.DescriptorSize;
                        if (buildIdSize > 0x20)
                        {
                            buildIdSize = 0x20;
                        }
                        Array.Copy(noteDesc.ReadArray(0, (int)buildIdSize), nsoHeader.BuildId, buildIdSize);
                    }
                }
                currentSectionHeaderOffset += header.SHEntSize;
            }

            var headerData = nsoHeader.ToByteArray();
            var buffer = new List<byte>(headerData.Length + nsoHeader.CompSz.Cast<int>().Sum());
            buffer.AddRange(headerData);
            for (int i = 0; i < nsoHeader.CompSz.Length; i++)
            {
                buffer.AddRange(compressedBuffers[i].Take((int)nsoHeader.CompSz[i]));
            }
            return buffer.ToArray();
        }

        private struct NsoSegment
        {
            public uint FileOff { get; set; }
            public uint DstOff { get; set; }
            public uint DecompSz { get; set; }
            public uint AlignOrTotalSz { get; set; }

            public byte[] ToByteArray()
            {
                var buffer = new byte[0x10];
                BitConverter.GetBytes(FileOff).CopyTo(buffer, 0);
                BitConverter.GetBytes(DstOff).CopyTo(buffer, 4);
                BitConverter.GetBytes(DecompSz).CopyTo(buffer, 8);
                BitConverter.GetBytes(AlignOrTotalSz).CopyTo(buffer, 12);
                return buffer;
            }
        }

        private class NsoHeader
        {
            public const int Length = 0x10 + 0x30 + 0x20 + 12 + 0x24 + 16 + 3 * 0x20;

            public NsoHeader()
            {
                Magic = Encoding.ASCII.GetBytes("NSO0");
                Unk3 = 0x3f;
                Segments = new NsoSegment[3];
                BuildId = new byte[0x20];
                CompSz = new uint[3];
                Padding = new byte[0x24];

                this.Hashes = new List<byte[]>
                {
                    new byte[0x20],
                    new byte[0x20],
                    new byte[0x20]
                };
            }

            public byte[] ToByteArray()
            {
                var buffer = new List<byte>(Length);
                buffer.AddRange(Magic);
                buffer.AddRange(BitConverter.GetBytes(Unk1));
                buffer.AddRange(BitConverter.GetBytes(Unk2));
                buffer.AddRange(BitConverter.GetBytes(Unk3));
                foreach (var segment in Segments)
                {
                    buffer.AddRange(segment.ToByteArray());
                }
                buffer.AddRange(BuildId);
                foreach (var size in CompSz)
                {
                    buffer.AddRange(BitConverter.GetBytes(size));
                }
                buffer.AddRange(Padding);
                buffer.AddRange(BitConverter.GetBytes(Unk4));
                buffer.AddRange(BitConverter.GetBytes(Unk5));
                foreach (var hash in Hashes)
                {
                    buffer.AddRange(hash);
                }
                return buffer.ToArray();
            }

            public byte[] Magic { get; } // Length: 4
            public uint Unk1 { get; set; }
            public uint Unk2 { get; set; }
            public uint Unk3 { get; set; }
            public NsoSegment[] Segments { get; set; } // Length: 3
            public byte[] BuildId { get; set; } // Length: 0x20
            public uint[] CompSz { get; set; } // Length: 3
            public byte[] Padding { get; set; }
            public ulong Unk4 { get; set; }
            public ulong Unk5 { get; set; }
            public IList<byte[]> Hashes { get; set; } // 3 sets of byte[] length 0x20
        }
    }
}
