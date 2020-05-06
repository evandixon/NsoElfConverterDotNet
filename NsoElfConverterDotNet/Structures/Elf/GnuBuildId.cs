using System;
using System.Collections.Generic;
using System.Text;

namespace NsoElfConverterDotNet.Structures.Elf
{
    public struct GnuBuildId
    {
        public Elf64Nhdr Header { get; set; }
        public char[] Owner { get; set; } // Length: 4
        public byte[] BuildIdRaw { get; set; } // Length: 32
    }
}
