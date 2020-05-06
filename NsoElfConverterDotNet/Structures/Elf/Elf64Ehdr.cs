using SkyEditor.IO.Binary;
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Text;

namespace NsoElfConverterDotNet.Structures.Elf
{
    // Copyright (c) 1996-1998 John D. Polstra.
    // All rights reserved.
    // 
    // Redistribution and use in source and binary forms, with or without
    // modification, are permitted provided that the following conditions
    // are met:
    // 1. Redistributions of source code must retain the above copyright
    //    notice, this list of conditions and the following disclaimer.
    // 2. Redistributions in binary form must reproduce the above copyright
    //    notice, this list of conditions and the following disclaimer in the
    //    documentation and/or other materials provided with the distribution.
    // 
    // THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
    // ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
    // IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
    // ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
    // FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
    // DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
    // OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
    // HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
    // LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
    // OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
    // SUCH DAMAGE.
    // 
    // $FreeBSD: head/sys/sys/elf64.h 186667 2009-01-01 02:08:56Z obrien $
    // 

    // This has been modified for use with C#

    public class Elf64Ehdr
    {
        public const int Length = ElfConstants.EI_NIDENT + 48;

        public Elf64Ehdr()
        {
            Ident = new byte[ElfConstants.EI_NIDENT];
        }

        public Elf64Ehdr(IReadOnlyBinaryDataAccessor data)
        {
            Ident = data.ReadArray(0, ElfConstants.EI_NIDENT);

            var index = ElfConstants.EI_NIDENT;

            Type = data.ReadUInt16(index); index += 2;
            Machine = data.ReadUInt16(index); index += 2;
            Version = data.ReadUInt32(index); index += 4;
            Entry = data.ReadUInt64(index); index += 8;
            PhOff = data.ReadUInt64(index); index += 8;
            ShOff = data.ReadUInt64(index); index += 8;
            Flags = data.ReadUInt32(index); index += 4;
            EhSize = data.ReadUInt16(index); index += 2;
            PHEntSize = data.ReadUInt16(index); index += 2;
            PHNum = data.ReadUInt16(index); index += 2;
            SHEntSize = data.ReadUInt16(index); index += 2;
            SHNum = data.ReadUInt16(index); index += 2;
            SHStrNdx = data.ReadUInt16(index); index += 2;
        }

        public void Write(Span<byte> data)
        {
            Ident.CopyTo(data);
            var index = ElfConstants.EI_NIDENT;
            BinaryPrimitives.WriteUInt16LittleEndian(data.Slice(index), Type); index += 2;
            BinaryPrimitives.WriteUInt16LittleEndian(data.Slice(index), Machine); index += 2;
            BinaryPrimitives.WriteUInt32LittleEndian(data.Slice(index), Version); index += 4;
            BinaryPrimitives.WriteUInt64LittleEndian(data.Slice(index), Entry); index += 8;
            BinaryPrimitives.WriteUInt64LittleEndian(data.Slice(index), PhOff); index += 8;
            BinaryPrimitives.WriteUInt64LittleEndian(data.Slice(index), ShOff); index += 8;
            BinaryPrimitives.WriteUInt32LittleEndian(data.Slice(index), Flags); index += 4;
            BinaryPrimitives.WriteUInt16LittleEndian(data.Slice(index), EhSize); index += 2;
            BinaryPrimitives.WriteUInt16LittleEndian(data.Slice(index), PHEntSize); index += 2;
            BinaryPrimitives.WriteUInt16LittleEndian(data.Slice(index), PHNum); index += 2;
            BinaryPrimitives.WriteUInt16LittleEndian(data.Slice(index), SHEntSize); index += 2;
            BinaryPrimitives.WriteUInt16LittleEndian(data.Slice(index), SHNum); index += 2;
            BinaryPrimitives.WriteUInt16LittleEndian(data.Slice(index), SHStrNdx); index += 2;
        }

        /// <summary>
        /// File identification
        /// </summary>
        public byte[] Ident { get; set; }

        /// <summary>
        /// File type
        /// </summary>
        public ushort Type { get; set; }

        /// <summary>
        /// Machine architecture
        /// </summary>
        public ushort Machine { get; set; }

        /// <summary>
        /// ELF format version
        /// </summary>
        public uint Version { get; set; }

        /// <summary>
        /// Entry point
        /// </summary>
        public ulong Entry { get; set; }

        /// <summary>
        /// Program header file offset
        /// </summary>
        public ulong PhOff { get; set; }

        /// <summary>
        /// Section header file offset
        /// </summary>
        public ulong ShOff { get; set; }

        /// <summary>
        /// Architecture-specific flags
        /// </summary>
        public uint Flags { get; set; }

        /// <summary>
        /// Size of ELF header in bytes
        /// </summary>
        public ushort EhSize { get; set; }

        /// <summary>
        /// Size of program header entry
        /// </summary>
        public ushort PHEntSize { get; set; }

        /// <summary>
        /// Number of program header entries
        /// </summary>
        public ushort PHNum { get; set; }

        /// <summary>
        /// Size of section header entry
        /// </summary>
        public ushort SHEntSize { get; set; }

        /// <summary>
        /// Number of section header entries
        /// </summary>
        public ushort SHNum { get; set; }

        /// <summary>
        /// Section name strings section
        /// </summary>
        public ushort SHStrNdx { get; set; }
    }
}
