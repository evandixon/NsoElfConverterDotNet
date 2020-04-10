using SkyEditor.IO.Binary;
using System;
using System.Collections.Generic;
using System.Text;

namespace NsoElfConverterDotNet.Elf2Nso
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

        public Elf64Phdr(IReadOnlyBinaryDataAccessor data)
        {
            var index = 0;
            Type = data.ReadUInt32(index); index += 4;
            Flags = data.ReadUInt32(index); index += 4;
            Offset = data.ReadUInt64(index); index += 8;
            VAddr = data.ReadUInt64(index); index += 8;
            PAddr = data.ReadUInt64(index); index += 8;
            FileSize = data.ReadUInt64(index); index += 8;
            MemSize = data.ReadUInt64(index); index += 8;
            Align = data.ReadUInt64(index); index += 8;
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
