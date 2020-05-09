using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Text;

namespace NsoElfConverterDotNet.Structures.Elf
{
    public struct Elf64Sym
    {
        public const int Length = 4 + 1 + 1 + 2 + 8 + 8;

        public Elf64Sym(ReadOnlySpan<byte> data)
        {
            Name = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(0, 4));
            Info = data[4];
            Other = data[5];
            Shndx = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(6, 2));
            Value = BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(8, 8));
            Size = BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(16, 8));
        }

        public uint Name { get; set; }
        public byte Info { get; set; }
        public byte Other { get; set; }
        public ushort Shndx { get; set; }
        public ulong Value { get; set; }
        public ulong Size { get; set; }
    }
}
