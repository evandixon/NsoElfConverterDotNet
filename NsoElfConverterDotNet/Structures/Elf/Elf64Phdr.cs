﻿using System;
using System.Buffers.Binary;

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

    public class Elf64Phdr
    {
        public const int Length = 56;

        public Elf64Phdr()
        {
        }

        public Elf64Phdr(ReadOnlySpan<byte> data)
        {
            var index = 0;
            Type = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(index)); index += 4;
            Flags = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(index)); index += 4;
            Offset = BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(index)); index += 8;
            VAddr = BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(index)); index += 8;
            PAddr = BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(index)); index += 8;
            FileSize = BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(index)); index += 8;
            MemSize = BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(index)); index += 8;
            Align = BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(index)); index += 8;
        }

        public void Write(Span<byte> data)
        {
            var index = 0;
            BinaryPrimitives.WriteUInt32LittleEndian(data.Slice(index), Type); index += 4;
            BinaryPrimitives.WriteUInt32LittleEndian(data.Slice(index), Flags); index += 4;
            BinaryPrimitives.WriteUInt64LittleEndian(data.Slice(index), Offset); index += 8;
            BinaryPrimitives.WriteUInt64LittleEndian(data.Slice(index), VAddr); index += 8;
            BinaryPrimitives.WriteUInt64LittleEndian(data.Slice(index), PAddr); index += 8;
            BinaryPrimitives.WriteUInt64LittleEndian(data.Slice(index), FileSize); index += 8;
            BinaryPrimitives.WriteUInt64LittleEndian(data.Slice(index), MemSize); index += 8;
            BinaryPrimitives.WriteUInt64LittleEndian(data.Slice(index), Align); index += 8;
        }

        /// <summary>
        /// Entry type
        /// </summary>
        public uint Type { get; set; }

        /// <summary>
        /// Access permission flags
        /// </summary>
        public uint Flags { get; set; }

        /// <summary>
        /// File offset of contents
        /// </summary>
        public ulong Offset { get; set; }

        /// <summary>
        /// Virtual address in memory image
        /// </summary>
        public ulong VAddr { get; set; }

        /// <summary>
        /// Physical address (not used)
        /// </summary>
        public ulong PAddr { get; set; }

        /// <summary>
        /// Size of contents in file
        /// </summary>
        public ulong FileSize { get; set; }

        /// <summary>
        /// Size of contents in memory
        /// </summary>
        public ulong MemSize { get; set; }

        /// <summary>
        /// Alignment in memory and file
        /// </summary>
        public ulong Align { get; set; }
    }
}
