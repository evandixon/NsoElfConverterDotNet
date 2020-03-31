using SkyEditor.IO.Binary;
using System;
using System.Collections.Generic;
using System.Text;

namespace NsoElfConverterDotNet.Elf2Nso
{
    public class Elf64Shdr
    {
        public const int Length = 64;

        public Elf64Shdr(IReadOnlyBinaryDataAccessor data)
        {
            var index = 0;
            Name = data.ReadUInt32(index); index += 4;
            Type = data.ReadUInt32(index); index += 4;
            Flags = data.ReadUInt64(index); index += 8;
            Addr = data.ReadUInt64(index); index += 8;
            Offset = data.ReadUInt64(index); index += 8;
            Size = data.ReadUInt64(index); index += 8;
            Link = data.ReadUInt32(index); index += 4;
            Info = data.ReadUInt32(index); index += 4;
            AddrAlign = data.ReadUInt64(index); index += 8;
            EntSize = data.ReadUInt64(index); index += 8;
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
