﻿using System;
using System.Buffers.Binary;

namespace NsoElfConverterDotNet.Structures.Elf
{
    public class Elf64Shdr
    {
        public const int Length = 64;

        public Elf64Shdr()
        {
        }

        public Elf64Shdr(ReadOnlySpan<byte> data)
        {
            var index = 0;
            Name = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(index)); index += 4;
            Type = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(index)); index += 4;
            Flags = BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(index)); index += 8;
            Addr = BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(index)); index += 8;
            Offset = BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(index)); index += 8;
            Size = BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(index)); index += 8;
            Link = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(index)); index += 4;
            Info = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(index)); index += 4;
            AddrAlign = BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(index)); index += 8;
            EntSize = BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(index)); index += 8;
        }

        public void Write(Span<byte> data)
        {
            var index = 0;
            BinaryPrimitives.WriteUInt32LittleEndian(data.Slice(index), Name); index += 4;
            BinaryPrimitives.WriteUInt32LittleEndian(data.Slice(index), Type); index += 4;
            BinaryPrimitives.WriteUInt64LittleEndian(data.Slice(index), Flags); index += 8;
            BinaryPrimitives.WriteUInt64LittleEndian(data.Slice(index), Addr); index += 8;
            BinaryPrimitives.WriteUInt64LittleEndian(data.Slice(index), Offset); index += 8;
            BinaryPrimitives.WriteUInt64LittleEndian(data.Slice(index), Size); index += 8;
            BinaryPrimitives.WriteUInt32LittleEndian(data.Slice(index), Link); index += 4;
            BinaryPrimitives.WriteUInt32LittleEndian(data.Slice(index), Info); index += 4;
            BinaryPrimitives.WriteUInt64LittleEndian(data.Slice(index), AddrAlign); index += 8;
            BinaryPrimitives.WriteUInt64LittleEndian(data.Slice(index), EntSize); index += 8;
        }

        /// <summary>
        /// Section name (index into the section header string table)
        /// </summary>
        public uint Name { get; set; }

        /// <summary>
        /// Section type
        /// </summary>
        public uint Type { get; set; }

        /// <summary>
        /// Section flags
        /// </summary>
        public ulong Flags { get; set; }

        /// <summary>
        /// Address in memory image
        /// </summary>
        public ulong Addr { get; set; }

        /// <summary>
        /// Offset in file
        /// </summary>
        public ulong Offset { get; set; }

        /// <summary>
        /// Size in bytes
        /// </summary>
        public ulong Size { get; set; }

        /// <summary>
        /// Index of a related section
        /// </summary>
        public uint Link { get; set; }

        /// <summary>
        /// Depends on section type
        /// </summary>
        public uint Info { get; set; }

        /// <summary>
        /// Alignment in bytes
        /// </summary>
        public ulong AddrAlign { get; set; }

        /// <summary>
        /// Size of each entry in section
        /// </summary>
        public ulong EntSize { get; set; }
    }
}
