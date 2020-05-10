using System;
using System.Buffers.Binary;

namespace NsoElfConverterDotNet.Structures.Elf
{
    public struct Elf64Rela
    {
        public const int Length = 3 * 8;

        public Elf64Rela(ReadOnlySpan<byte> data)
        {
            Offset = BinaryPrimitives.ReadUInt64LittleEndian(data);
            Info = BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(8));
            Addend = BinaryPrimitives.ReadInt64LittleEndian(data.Slice(16));
        }
        
        public ulong Offset { get; set; }
        public ulong Info { get; set; }
        public long Addend { get; set; }
    }
}
