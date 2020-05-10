using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Text;

namespace NsoElfConverterDotNet.Structures.Elf
{
    public struct Elf64Dyn
    {
        public const int Length = 8 + 8;

        public Elf64Dyn(ReadOnlySpan<byte> data)
        {
            Tag = BinaryPrimitives.ReadUInt64LittleEndian(data);
            Un = BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(8));
        }

        public ulong Tag { get; set; }
        public ulong Un { get; set; }
    }
}
