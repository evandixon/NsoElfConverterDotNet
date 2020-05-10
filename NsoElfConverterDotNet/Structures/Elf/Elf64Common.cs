namespace NsoElfConverterDotNet.Structures.Elf
{
    // Copyright (c) 2000, 2001, 2008, 2011, David E. O'Brien
    // Copyright (c) 1998 John D. Polstra.
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
    // $FreeBSD: head/sys/sys/elf_common.h 273284 2014-10-19 20:23:31Z andrew $

    // This has been modified for use with C#

    //
    // ELF definitions that are independent of architecture or word size.
    //

    /// <summary>
    /// The header for GNU-style hash sections.
    /// </summary>
    public struct ElfGnuHashHeader
    {
        /// <summary>
        /// Number of hash buckets.
        /// </summary>
        public uint BucketCount { get; set; }

        /// <summary>
        /// First visible symbol in .dynsym.
        /// </summary>
        public uint Symndx { get; set; }

        /// <summary>
        /// #maskwords used in bloom filter.
        /// </summary>
        public uint MaskWords { get; set; }

        /// <summary>
        /// Bloom filter shift count.
        /// </summary>
        public uint Shift2 { get; set; }
    }

    /// <summary>
    /// Indexes into the e_ident array.  Keep synced with http://www.sco.com/developers/gabi/latest/ch4.eheader.html
    /// </summary>
    public static class ElfConstants
    {
        public const int EI_MAG0 = 0;  /* Magic number, byte 0. */
        public const int EI_MAG1 = 1;  /* Magic number, byte 1. */
        public const int EI_MAG2 = 2;  /* Magic number, byte 2. */
        public const int EI_MAG3 = 3;  /* Magic number, byte 3. */
        public const int EI_CLASS = 4; /* Class of machine. */
        public const int EI_DATA = 5;  /* Data format. */
        public const int EI_VERSION = 6;   /* ELF format version. */
        public const int EI_OSABI = 7; /* Operating system / ABI identification */
        public const int EI_ABIVERSION = 8;    /* ABI version */
        public const int OLD_EI_BRAND = 8; /* Start of architecture identification. */
        public const int EI_PAD = 9;   /* Start of padding (per SVR4 ABI). */
        public const int EI_NIDENT = 16;   /* Size of e_ident array. */

        /* Values for the magic number bytes. */
        public const int ELFMAG0 = 0x7f;
        public const int ELFMAG1 = 'E';
        public const int ELFMAG2 = 'L';
        public const int ELFMAG3 = 'F';
        public const string ELFMAG = "\x177ELF";
        public const int SELFMAG = 4;      /* magic string size */

        /* Values for e_ident[EI_VERSION] and e_version. */
        public const int EV_NONE = 0;
        public const int EV_CURRENT = 1;

        /* Values for e_ident[EI_CLASS]. */
        public const int ELFCLASSNONE = 0; /* Unknown class. */
        public const int ELFCLASS32 = 1;   /* 32-bit architecture. */
        public const int ELFCLASS64 = 2;   /* 64-bit architecture. */

        /* Values for e_ident[EI_DATA]. */
        public const int ELFDATANONE = 0;  /* Unknown data format. */
        public const int ELFDATA2LSB = 1;  /* 2's complement little-endian. */
        public const int ELFDATA2MSB = 2;  /* 2's complement big-endian. */

        /* Values for e_ident[EI_OSABI]. */
        public const int ELFOSABI_NONE = 0;    /* UNIX System V ABI */
        public const int ELFOSABI_HPUX = 1;    /* HP-UX operating system */
        public const int ELFOSABI_NETBSD = 2;  /* NetBSD */
        public const int ELFOSABI_LINUX = 3;   /* GNU/Linux */
        public const int ELFOSABI_HURD = 4;    /* GNU/Hurd */
        public const int ELFOSABI_86OPEN = 5;  /* 86Open common IA32 ABI */
        public const int ELFOSABI_SOLARIS = 6; /* Solaris */
        public const int ELFOSABI_AIX = 7; /* AIX */
        public const int ELFOSABI_IRIX = 8;    /* IRIX */
        public const int ELFOSABI_FREEBSD = 9; /* FreeBSD */
        public const int ELFOSABI_TRU64 = 10;  /* TRU64 UNIX */
        public const int ELFOSABI_MODESTO = 11;    /* Novell Modesto */
        public const int ELFOSABI_OPENBSD = 12;    /* OpenBSD */
        public const int ELFOSABI_OPENVMS = 13;    /* Open VMS */
        public const int ELFOSABI_NSK = 14;    /* HP Non-Stop Kernel */
        public const int ELFOSABI_AROS = 15;   /* Amiga Research OS */
        public const int ELFOSABI_ARM = 97;    /* ARM */
        public const int ELFOSABI_STANDALONE = 255;    /* Standalone (embedded) application */

        public const int ELFOSABI_SYSV = ELFOSABI_NONE;    /* symbol used in old spec */
        public const int ELFOSABI_MONTEREY = ELFOSABI_AIX;    /* Monterey */

        /* e_ident */
        public static bool IS_ELF(dynamic ehdr)
        {
            return (ehdr.e_ident[EI_MAG0] == ELFMAG0 &&
             ehdr.e_ident[EI_MAG1] == ELFMAG1 &&
             ehdr.e_ident[EI_MAG2] == ELFMAG2 &&
             ehdr.e_ident[EI_MAG3] == ELFMAG3);
        }

        /* Values for e_type. */
        public const int ET_NONE = 0;  /* Unknown type. */
        public const int ET_REL = 1;   /* Relocatable. */
        public const int ET_EXEC = 2;  /* Executable. */
        public const int ET_DYN = 3;   /* Shared object. */
        public const int ET_CORE = 4;  /* Core file. */
        public const int ET_LOOS = 0xfe00; /* First operating system specific. */
        public const int ET_HIOS = 0xfeff; /* Last operating system-specific. */
        public const int ET_LOPROC = 0xff00;   /* First processor-specific. */
        public const int ET_HIPROC = 0xffff;   /* Last processor-specific. */

        /* Values for e_machine. */
        public const int EM_NONE = 0;  /* Unknown machine. */
        public const int EM_M32 = 1;   /* AT&T WE32100. */
        public const int EM_SPARC = 2; /* Sun SPARC. */
        public const int EM_386 = 3;   /* Intel i386. */
        public const int EM_68K = 4;   /* Motorola 68000. */
        public const int EM_88K = 5;   /* Motorola 88000. */
        public const int EM_860 = 7;   /* Intel i860. */
        public const int EM_MIPS = 8;  /* MIPS R3000 Big-Endian only. */
        public const int EM_S370 = 9;  /* IBM System/370. */
        public const int EM_MIPS_RS3_LE = 10;  /* MIPS R3000 Little-Endian. */
        public const int EM_PARISC = 15;   /* HP PA-RISC. */
        public const int EM_VPP500 = 17;   /* Fujitsu VPP500. */
        public const int EM_SPARC32PLUS = 18;  /* SPARC v8plus. */
        public const int EM_960 = 19;  /* Intel 80960. */
        public const int EM_PPC = 20;  /* PowerPC 32-bit. */
        public const int EM_PPC64 = 21;    /* PowerPC 64-bit. */
        public const int EM_S390 = 22; /* IBM System/390. */
        public const int EM_V800 = 36; /* NEC V800. */
        public const int EM_FR20 = 37; /* Fujitsu FR20. */
        public const int EM_RH32 = 38; /* TRW RH-32. */
        public const int EM_RCE = 39;  /* Motorola RCE. */
        public const int EM_ARM = 40;  /* ARM. */
        public const int EM_SH = 42;   /* Hitachi SH. */
        public const int EM_SPARCV9 = 43;  /* SPARC v9 64-bit. */
        public const int EM_TRICORE = 44;  /* Siemens TriCore embedded processor. */
        public const int EM_ARC = 45;  /* Argonaut RISC Core. */
        public const int EM_H8_300 = 46;   /* Hitachi H8/300. */
        public const int EM_H8_300H = 47;  /* Hitachi H8/300H. */
        public const int EM_H8S = 48;  /* Hitachi H8S. */
        public const int EM_H8_500 = 49;   /* Hitachi H8/500. */
        public const int EM_IA_64 = 50;    /* Intel IA-64 Processor. */
        public const int EM_MIPS_X = 51;   /* Stanford MIPS-X. */
        public const int EM_COLDFIRE = 52; /* Motorola ColdFire. */
        public const int EM_68HC12 = 53;   /* Motorola M68HC12. */
        public const int EM_MMA = 54;  /* Fujitsu MMA. */
        public const int EM_PCP = 55;  /* Siemens PCP. */
        public const int EM_NCPU = 56; /* Sony nCPU. */
        public const int EM_NDR1 = 57; /* Denso NDR1 microprocessor. */
        public const int EM_STARCORE = 58; /* Motorola Star*Core processor. */
        public const int EM_ME16 = 59; /* Toyota ME16 processor. */
        public const int EM_ST100 = 60;    /* STMicroelectronics ST100 processor. */
        public const int EM_TINYJ = 61;    /* Advanced Logic Corp. TinyJ processor. */
        public const int EM_X86_64 = 62;   /* Advanced Micro Devices x86-64 */
        public const int EM_AMD64 = EM_X86_64; /* Advanced Micro Devices x86-64 (compat) */
        public const int EM_PDSP = 63; /* Sony DSP Processor. */
        public const int EM_FX66 = 66; /* Siemens FX66 microcontroller. */
        public const int EM_ST9PLUS = 67;  /* STMicroelectronics ST9+ 8/16
				   microcontroller. */
        public const int EM_ST7 = 68;  /* STmicroelectronics ST7 8-bit
				   microcontroller. */
        public const int EM_68HC16 = 69;   /* Motorola MC68HC16 microcontroller. */
        public const int EM_68HC11 = 70;   /* Motorola MC68HC11 microcontroller. */
        public const int EM_68HC08 = 71;   /* Motorola MC68HC08 microcontroller. */
        public const int EM_68HC05 = 72;   /* Motorola MC68HC05 microcontroller. */
        public const int EM_SVX = 73;  /* Silicon Graphics SVx. */
        public const int EM_ST19 = 74; /* STMicroelectronics ST19 8-bit mc. */
        public const int EM_VAX = 75;  /* Digital VAX. */
        public const int EM_CRIS = 76; /* Axis Communications 32-bit embedded
				   processor. */
        public const int EM_JAVELIN = 77;  /* Infineon Technologies 32-bit embedded
				   processor. */
        public const int EM_FIREPATH = 78; /* Element 14 64-bit DSP Processor. */
        public const int EM_ZSP = 79;  /* LSI Logic 16-bit DSP Processor. */
        public const int EM_MMIX = 80; /* Donald Knuth's educational 64-bit proc. */
        public const int EM_HUANY = 81;    /* Harvard University machine-independent
				   object files. */
        public const int EM_PRISM = 82;    /* SiTera Prism. */
        public const int EM_AVR = 83;  /* Atmel AVR 8-bit microcontroller. */
        public const int EM_FR30 = 84; /* Fujitsu FR30. */
        public const int EM_D10V = 85; /* Mitsubishi D10V. */
        public const int EM_D30V = 86; /* Mitsubishi D30V. */
        public const int EM_V850 = 87; /* NEC v850. */
        public const int EM_M32R = 88; /* Mitsubishi M32R. */
        public const int EM_MN10300 = 89;  /* Matsushita MN10300. */
        public const int EM_MN10200 = 90;  /* Matsushita MN10200. */
        public const int EM_PJ = 91;   /* picoJava. */
        public const int EM_OPENRISC = 92; /* OpenRISC 32-bit embedded processor. */
        public const int EM_ARC_A5 = 93;   /* ARC Cores Tangent-A5. */
        public const int EM_XTENSA = 94;   /* Tensilica Xtensa Architecture. */
        public const int EM_VIDEOCORE = 95;    /* Alphamosaic VideoCore processor. */
        public const int EM_TMM_GPP = 96;  /* Thompson Multimedia General Purpose
				   Processor. */
        public const int EM_NS32K = 97;    /* National Semiconductor 32000 series. */
        public const int EM_TPC = 98;  /* Tenor Network TPC processor. */
        public const int EM_SNP1K = 99;    /* Trebia SNP 1000 processor. */
        public const int EM_ST200 = 100;   /* STMicroelectronics ST200 microcontroller. */
        public const int EM_IP2K = 101;    /* Ubicom IP2xxx microcontroller family. */
        public const int EM_MAX = 102; /* MAX Processor. */
        public const int EM_CR = 103;  /* National Semiconductor CompactRISC
                   microprocessor. */
        public const int EM_F2MC16 = 104;  /* Fujitsu F2MC16. */
        public const int EM_MSP430 = 105;  /* Texas Instruments embedded microcontroller
                   msp430. */
        public const int EM_BLACKFIN = 106;    /* Analog Devices Blackfin (DSP) processor. */
        public const int EM_SE_C33 = 107;  /* S1C33 Family of Seiko Epson processors. */
        public const int EM_SEP = 108; /* Sharp embedded microprocessor. */
        public const int EM_ARCA = 109;    /* Arca RISC Microprocessor. */
        public const int EM_UNICORE = 110; /* Microprocessor series from PKU-Unity Ltd.
                   and MPRC of Peking University*/
        public const int EM_AARCH64 = 183; /* AArch64 (64-bit ARM) */

        /* Non-standard or deprecated. */
        public const int EM_486 = 6;   /* Intel i486. */
        public const int EM_MIPS_RS4_BE = 10;  /* MIPS R4000 Big-Endian */
        public const int EM_ALPHA_STD = 41;    /* Digital Alpha (standard value). */
        public const int EM_ALPHA = 0x9026;    /* Alpha (written in the absence of an ABI) */

        /* Special section indexes. */
        public const int SHN_UNDEF = 0;        /* Undefined, missing, irrelevant. */
        public const int SHN_LORESERVE = 0xff00;       /* First of reserved range. */
        public const int SHN_LOPROC = 0xff00;      /* First processor-specific. */
        public const int SHN_HIPROC = 0xff1f;      /* Last processor-specific. */
        public const int SHN_LOOS = 0xff20;        /* First operating system-specific. */
        public const int SHN_HIOS = 0xff3f;        /* Last operating system-specific. */
        public const int SHN_ABS = 0xfff1;     /* Absolute values. */
        public const int SHN_COMMON = 0xfff2;      /* Common data. */
        public const int SHN_XINDEX = 0xffff;      /* Escape -- index stored elsewhere. */
        public const int SHN_HIRESERVE = 0xffff;       /* Last of reserved range. */

        /* sh_type */
        public const int SHT_NULL = 0; /* inactive */
        public const int SHT_PROGBITS = 1; /* program defined information */
        public const int SHT_SYMTAB = 2;   /* symbol table section */
        public const int SHT_STRTAB = 3;   /* string table section */
        public const int SHT_RELA = 4; /* relocation section with addends */
        public const int SHT_HASH = 5; /* symbol hash table section */
        public const int SHT_DYNAMIC = 6;  /* dynamic section */
        public const int SHT_NOTE = 7; /* note section */
        public const int SHT_NOBITS = 8;   /* no space section */
        public const int SHT_REL = 9;  /* relocation section - no addends */
        public const int SHT_SHLIB = 10;   /* reserved - purpose unknown */
        public const int SHT_DYNSYM = 11;  /* dynamic symbol table section */
        public const int SHT_INIT_ARRAY = 14;  /* Initialization function pointers. */
        public const int SHT_FINI_ARRAY = 15;  /* Termination function pointers. */
        public const int SHT_PREINIT_ARRAY = 16;   /* Pre-initialization function ptrs. */
        public const int SHT_GROUP = 17;   /* Section group. */
        public const int SHT_SYMTAB_SHNDX = 18;    /* Section indexes (see SHN_XINDEX). */
        public const int SHT_LOOS = 0x60000000;    /* First of OS specific semantics */
        public const int SHT_LOSUNW = 0x6ffffff4;
        public const int SHT_SUNW_dof = 0x6ffffff4;
        public const int SHT_SUNW_cap = 0x6ffffff5;
        public const int SHT_SUNW_SIGNATURE = 0x6ffffff6;
        public const int SHT_GNU_HASH = 0x6ffffff6;
        public const int SHT_GNU_LIBLIST = 0x6ffffff7;
        public const int SHT_SUNW_ANNOTATE = 0x6ffffff7;
        public const int SHT_SUNW_DEBUGSTR = 0x6ffffff8;
        public const int SHT_SUNW_DEBUG = 0x6ffffff9;
        public const int SHT_SUNW_move = 0x6ffffffa;
        public const int SHT_SUNW_COMDAT = 0x6ffffffb;
        public const int SHT_SUNW_syminfo = 0x6ffffffc;
        public const int SHT_SUNW_verdef = 0x6ffffffd;
        public const int SHT_GNU_verdef = 0x6ffffffd;  /* Symbol versions provided */
        public const int SHT_SUNW_verneed = 0x6ffffffe;
        public const int SHT_GNU_verneed = 0x6ffffffe; /* Symbol versions required */
        public const int SHT_SUNW_versym = 0x6fffffff;
        public const int SHT_GNU_versym = 0x6fffffff;  /* Symbol version table */
        public const int SHT_HISUNW = 0x6fffffff;
        public const int SHT_HIOS = 0x6fffffff;    /* Last of OS specific semantics */
        public const int SHT_LOPROC = 0x70000000;  /* reserved range for processor */
        public const int SHT_AMD64_UNWIND = 0x70000001;    /* unwind information */
        public const int SHT_ARM_EXIDX = 0x70000001;   /* Exception index table. */
        public const int SHT_ARM_PREEMPTMAP = 0x70000002;  /* BPABI DLL dynamic linking 
                           pre-emption map. */
        public const int SHT_ARM_ATTRIBUTES = 0x70000003;  /* Object file compatibility 
                           attributes. */
        public const int SHT_ARM_DEBUGOVERLAY = 0x70000004;    /* See DBGOVL for details. */
        public const int SHT_ARM_OVERLAYSECTION = 0x70000005;  /* See DBGOVL for details. */
        public const int SHT_MIPS_REGINFO = 0x70000006;
        public const int SHT_MIPS_OPTIONS = 0x7000000d;
        public const int SHT_MIPS_DWARF = 0x7000001e;  /* MIPS gcc uses MIPS_DWARF */
        public const int SHT_HIPROC = 0x7fffffff;  /* specific section header types */
        public const uint SHT_LOUSER = 0x80000000;  /* reserved range for application */
        public const uint SHT_HIUSER = 0xffffffff;  /* specific indexes */

        /* Flags for sh_flags. */
        public const int SHF_WRITE = 0x1;  /* Section contains writable data. */
        public const int SHF_ALLOC = 0x2;  /* Section occupies memory. */
        public const int SHF_EXECINSTR = 0x4;  /* Section contains instructions. */
        public const int SHF_MERGE = 0x10; /* Section may be merged. */
        public const int SHF_STRINGS = 0x20;   /* Section contains strings. */
        public const int SHF_INFO_LINK = 0x40; /* sh_info holds section index. */
        public const int SHF_LINK_ORDER = 0x80;    /* Special ordering requirements. */
        public const int SHF_OS_NONCONFORMING = 0x100; /* OS-specific processing required. */
        public const int SHF_GROUP = 0x200;    /* Member of section group. */
        public const int SHF_TLS = 0x400;  /* Section contains TLS data. */
        public const int SHF_MASKOS = 0x0ff00000;  /* OS-specific semantics. */
        public const uint SHF_MASKPROC = 0xf0000000;    /* Processor-specific semantics. */

        /* Values for p_type. */
        public const int PT_NULL = 0;  /* Unused entry. */
        public const int PT_LOAD = 1;  /* Loadable segment. */
        public const int PT_DYNAMIC = 2;   /* Dynamic linking information segment. */
        public const int PT_INTERP = 3;    /* Pathname of interpreter. */
        public const int PT_NOTE = 4;  /* Auxiliary information. */
        public const int PT_SHLIB = 5; /* Reserved (not used). */
        public const int PT_PHDR = 6;  /* Location of program header itself. */
        public const int PT_TLS = 7;   /* Thread local storage segment */
        public const int PT_LOOS = 0x60000000; /* First OS-specific. */
        public const int PT_SUNW_UNWIND = 0x6464e550;  /* amd64 UNWIND program header */
        public const int PT_GNU_EH_FRAME = 0x6474e550;
        public const int PT_GNU_STACK = 0x6474e551;
        public const int PT_GNU_RELRO = 0x6474e552;
        public const int PT_DUMP_DELTA = 0x6fb5d000;   /* va->pa map for kernel dumps
                       (currently arm). */
        public const int PT_LOSUNW = 0x6ffffffa;
        public const int PT_SUNWBSS = 0x6ffffffa;  /* Sun Specific segment */
        public const int PT_SUNWSTACK = 0x6ffffffb;    /* describes the stack segment */
        public const int PT_SUNWDTRACE = 0x6ffffffc;   /* private */
        public const int PT_SUNWCAP = 0x6ffffffd;  /* hard/soft capabilities segment */
        public const int PT_HISUNW = 0x6fffffff;
        public const int PT_HIOS = 0x6fffffff; /* Last OS-specific. */
        public const int PT_LOPROC = 0x70000000;   /* First processor-specific type. */
        public const int PT_HIPROC = 0x7fffffff;   /* Last processor-specific type. */

        /* Values for p_flags. */
        public const int PF_X = 0x1;       /* Executable. */
        public const int PF_W = 0x2;       /* Writable. */
        public const int PF_R = 0x4;       /* Readable. */
        public const int PF_MASKOS = 0x0ff00000;   /* Operating system-specific. */
        public const uint PF_MASKPROC = 0xf0000000; /* Processor-specific. */

        /* Extended program header index. */
        public const int PN_XNUM = 0xffff;

        /* Values for d_tag. */
        public const int DT_NULL = 0;  /* Terminating entry. */
        public const int DT_NEEDED = 1;    /* String table offset of a needed shared
                   library. */
        public const int DT_PLTRELSZ = 2;  /* Total size in bytes of PLT relocations. */
        public const int DT_PLTGOT = 3;    /* Processor-dependent address. */
        public const int DT_HASH = 4;  /* Address of symbol hash table. */
        public const int DT_STRTAB = 5;    /* Address of string table. */
        public const int DT_SYMTAB = 6;    /* Address of symbol table. */
        public const int DT_RELA = 7;  /* Address of ElfNN_Rela relocations. */
        public const int DT_RELASZ = 8;    /* Total size of ElfNN_Rela relocations. */
        public const int DT_RELAENT = 9;   /* Size of each ElfNN_Rela relocation entry. */
        public const int DT_STRSZ = 10;    /* Size of string table. */
        public const int DT_SYMENT = 11;   /* Size of each symbol table entry. */
        public const int DT_INIT = 12; /* Address of initialization function. */
        public const int DT_FINI = 13; /* Address of finalization function. */
        public const int DT_SONAME = 14;   /* String table offset of shared object
                   name. */
        public const int DT_RPATH = 15;    /* String table offset of library path. [sup] */
        public const int DT_SYMBOLIC = 16; /* Indicates "symbolic" linking. [sup] */
        public const int DT_REL = 17;  /* Address of ElfNN_Rel relocations. */
        public const int DT_RELSZ = 18;    /* Total size of ElfNN_Rel relocations. */
        public const int DT_RELENT = 19;   /* Size of each ElfNN_Rel relocation. */
        public const int DT_PLTREL = 20;   /* Type of relocation used for PLT. */
        public const int DT_DEBUG = 21;    /* Reserved (not used). */
        public const int DT_TEXTREL = 22;  /* Indicates there may be relocations in
                   non-writable segments. [sup] */
        public const int DT_JMPREL = 23;   /* Address of PLT relocations. */
        public const int DT_BIND_NOW = 24; /* [sup] */
        public const int DT_INIT_ARRAY = 25;   /* Address of the array of pointers to
                   initialization functions */
        public const int DT_FINI_ARRAY = 26;   /* Address of the array of pointers to
                   termination functions */
        public const int DT_INIT_ARRAYSZ = 27; /* Size in bytes of the array of
                   initialization functions. */
        public const int DT_FINI_ARRAYSZ = 28; /* Size in bytes of the array of
                   termination functions. */
        public const int DT_RUNPATH = 29;  /* String table offset of a null-terminated
                   library search path string. */
        public const int DT_FLAGS = 30;    /* Object specific flag values. */
        public const int DT_ENCODING = 32; /* Values greater than or equal to DT_ENCODING
                   and less than DT_LOOS follow the rules for

                   the interpretation of the d_un union
				   as follows: even == 'd_ptr', odd == 'd_val'

                   or none */
        public const int DT_PREINIT_ARRAY = 32;    /* Address of the array of pointers to
                   pre-initialization functions. */
        public const int DT_PREINIT_ARRAYSZ = 33;  /* Size in bytes of the array of
                   pre-initialization functions. */
        public const int DT_MAXPOSTAGS = 34;   /* number of positive tags */
        public const int DT_LOOS = 0x6000000d; /* First OS-specific */
        public const int DT_SUNW_AUXILIARY = 0x6000000d;   /* symbol auxiliary name */
        public const int DT_SUNW_RTLDINF = 0x6000000e; /* ld.so.1 info (private) */
        public const int DT_SUNW_FILTER = 0x6000000f;  /* symbol filter name */
        public const int DT_SUNW_CAP = 0x60000010; /* hardware/software */
        public const int DT_HIOS = 0x6ffff000; /* Last OS-specific */

        /*
         * DT_* entries which fall between DT_VALRNGHI & DT_VALRNGLO use the
         * Dyn.d_un.d_val field of the Elf*_Dyn structure.
         */
        public const int DT_VALRNGLO = 0x6ffffd00;
        public const int DT_CHECKSUM = 0x6ffffdf8; /* elf checksum */
        public const int DT_PLTPADSZ = 0x6ffffdf9; /* pltpadding size */
        public const int DT_MOVEENT = 0x6ffffdfa;  /* move table entry size */
        public const int DT_MOVESZ = 0x6ffffdfb;   /* move table size */
        public const int DT_FEATURE = 0x6ffffdfc;  /* feature holder */
        public const int DT_POSFLAG_1 = 0x6ffffdfd;    /* flags for DT_* entries, effecting */
        /*	the following DT_* entry. */
        /*	See DF_P1_* definitions */
        public const int DT_SYMINSZ = 0x6ffffdfe;  /* syminfo table size (in bytes) */
        public const int DT_SYMINENT = 0x6ffffdff; /* syminfo entry size (in bytes) */
        public const int DT_VALRNGHI = 0x6ffffdff;

        /*
         * DT_* entries which fall between DT_ADDRRNGHI & DT_ADDRRNGLO use the
         * Dyn.d_un.d_ptr field of the Elf*_Dyn structure.
         *
         * If any adjustment is made to the ELF object after it has been
         * built, these entries will need to be adjusted.
         */
        public const int DT_ADDRRNGLO = 0x6ffffe00;
        public const int DT_GNU_HASH = 0x6ffffef5; /* GNU-style hash table */
        public const int DT_CONFIG = 0x6ffffefa;   /* configuration information */
        public const int DT_DEPAUDIT = 0x6ffffefb; /* dependency auditing */
        public const int DT_AUDIT = 0x6ffffefc;    /* object auditing */
        public const int DT_PLTPAD = 0x6ffffefd;   /* pltpadding (sparcv9) */
        public const int DT_MOVETAB = 0x6ffffefe;  /* move table */
        public const int DT_SYMINFO = 0x6ffffeff;  /* syminfo table */
        public const int DT_ADDRRNGHI = 0x6ffffeff;

        public const int DT_VERSYM = 0x6ffffff0;   /* Address of versym section. */
        public const int DT_RELACOUNT = 0x6ffffff9;    /* number of RELATIVE relocations */
        public const int DT_RELCOUNT = 0x6ffffffa; /* number of RELATIVE relocations */
        public const int DT_FLAGS_1 = 0x6ffffffb;  /* state flags - see DF_1_* defs */
        public const int DT_VERDEF = 0x6ffffffc;   /* Address of verdef section. */
        public const int DT_VERDEFNUM = 0x6ffffffd;    /* Number of elems in verdef section */
        public const int DT_VERNEED = 0x6ffffffe;  /* Address of verneed section. */
        public const int DT_VERNEEDNUM = 0x6fffffff;   /* Number of elems in verneed section */

        public const int DT_LOPROC = 0x70000000;   /* First processor-specific type. */
        public const int DT_DEPRECATED_SPARC_REGISTER = 0x7000001;
        public const int DT_AUXILIARY = 0x7ffffffd;    /* shared library auxiliary name */
        public const int DT_USED = 0x7ffffffe; /* ignored - same as needed */
        public const int DT_FILTER = 0x7fffffff;   /* shared library filter name */
        public const int DT_HIPROC = 0x7fffffff;   /* Last processor-specific type. */

        /* Values for DT_FLAGS */
        public const int DF_ORIGIN = 0x0001;   /* Indicates that the object being loaded may
                   make reference to the $ORIGIN substitution

                   string*/
        public const int DF_SYMBOLIC = 0x0002; /* Indicates "symbolic" linking. */
        public const int DF_TEXTREL = 0x0004;  /* Indicates there may be relocations in
                   non-writable segments. */
        public const int DF_BIND_NOW = 0x0008; /* Indicates that the dynamic linker should
                   process all relocations for the object
                   containing this entry before transferring
                   control to the program. */
        public const int DF_STATIC_TLS = 0x0010;   /* Indicates that the shared object or
                   executable contains code using a static
                   thread-local storage scheme. */

        /* Values for DT_FLAGS_1 */
        public const int DF_1_BIND_NOW = 0x00000001;   /* Same as DF_BIND_NOW */
        public const int DF_1_GLOBAL = 0x00000002; /* Set the RTLD_GLOBAL for object */
        public const int DF_1_NODELETE = 0x00000008;   /* Set the RTLD_NODELETE for object */
        public const int DF_1_LOADFLTR = 0x00000010;   /* Immediate loading of filtees */
        public const int DF_1_NOOPEN = 0x00000040; /* Do not allow loading on dlopen() */
        public const int DF_1_ORIGIN = 0x00000080; /* Process $ORIGIN */
        public const int DF_1_INTERPOSE = 0x00000400;  /* Interpose all objects but main */
        public const int DF_1_NODEFLIB = 0x00000800;   /* Do not search default paths */

        /* Values for n_type.  Used in core files. */
        public const int NT_PRSTATUS = 1;  /* Process status. */
        public const int NT_FPREGSET = 2;  /* Floating point registers. */
        public const int NT_PRPSINFO = 3;  /* Process state info. */
        public const int NT_THRMISC = 7;   /* Thread miscellaneous info. */
        public const int NT_PROCSTAT_PROC = 8; /* Procstat proc data. */
        public const int NT_PROCSTAT_FILES = 9;    /* Procstat files data. */
        public const int NT_PROCSTAT_VMMAP = 10;   /* Procstat vmmap data. */
        public const int NT_PROCSTAT_GROUPS = 11;  /* Procstat groups data. */
        public const int NT_PROCSTAT_UMASK = 12;   /* Procstat umask data. */
        public const int NT_PROCSTAT_RLIMIT = 13;  /* Procstat rlimit data. */
        public const int NT_PROCSTAT_OSREL = 14;   /* Procstat osreldate data. */
        public const int NT_PROCSTAT_PSSTRINGS = 15;   /* Procstat ps_strings data. */
        public const int NT_PROCSTAT_AUXV = 16;    /* Procstat auxv data. */

        /* Symbol Binding - ELFNN_ST_BIND - st_info */
        public const int STB_LOCAL = 0;    /* Local symbol */
        public const int STB_GLOBAL = 1;   /* Global symbol */
        public const int STB_WEAK = 2; /* like global - lower precedence */
        public const int STB_LOOS = 10;    /* Reserved range for operating system */
        public const int STB_HIOS = 12;    /*   specific semantics. */
        public const int STB_LOPROC = 13;  /* reserved range for processor */
        public const int STB_HIPROC = 15;  /*   specific semantics. */

        /* Symbol type - ELFNN_ST_TYPE - st_info */
        public const int STT_NOTYPE = 0;   /* Unspecified type. */
        public const int STT_OBJECT = 1;   /* Data object. */
        public const int STT_FUNC = 2; /* Function. */
        public const int STT_SECTION = 3;  /* Section. */
        public const int STT_FILE = 4; /* Source file. */
        public const int STT_COMMON = 5;   /* Uninitialized common block. */
        public const int STT_TLS = 6;  /* TLS object. */
        public const int STT_NUM = 7;
        public const int STT_LOOS = 10;    /* Reserved range for operating system */
        public const int STT_GNU_IFUNC = 10;
        public const int STT_HIOS = 12;    /*   specific semantics. */
        public const int STT_LOPROC = 13;  /* reserved range for processor */
        public const int STT_HIPROC = 15;  /*   specific semantics. */

        /* Symbol visibility - ELFNN_ST_VISIBILITY - st_other */
        public const int STV_DEFAULT = 0x0;    /* Default visibility (see binding). */
        public const int STV_INTERNAL = 0x1;   /* Special meaning in relocatable objects. */
        public const int STV_HIDDEN = 0x2; /* Not visible. */
        public const int STV_PROTECTED = 0x3;  /* Visible but not preemptible. */
        public const int STV_EXPORTED = 0x4;
        public const int STV_SINGLETON = 0x5;
        public const int STV_ELIMINATE = 0x6;

        /* Special symbol table indexes. */
        public const int STN_UNDEF = 0;    /* Undefined symbol index. */

        /* Symbol versioning flags. */
        public const int VER_DEF_CURRENT = 1;
        public static long VER_DEF_IDX(long x) => VER_NDX(x);

        public const int VER_FLG_BASE = 0x01;
        public const int VER_FLG_WEAK = 0x02;

        public const int VER_NEED_CURRENT = 1;
        public const uint VER_NEED_WEAK = (1u << 15);
        public const uint VER_NEED_HIDDEN = VER_NDX_HIDDEN;
        public static long VER_NEED_IDX(long x) => VER_NDX(x);

        public const int VER_NDX_LOCAL = 0;
        public const int VER_NDX_GLOBAL = 1;
        public const int VER_NDX_GIVEN = 2;

        public const uint VER_NDX_HIDDEN = (1u << 15);
        public static long VER_NDX(long x)
        {
            return (x) & ~(1u << 15);
        }

        public const int CA_SUNW_NULL = 0;
        public const int CA_SUNW_HW_1 = 1;     /* first hardware capabilities entry */
        public const int CA_SUNW_SF_1 = 2;     /* first software capabilities entry */

        /*
         * Syminfo flag values
         */
        public const int SYMINFO_FLG_DIRECT = 0x0001;  /* symbol ref has direct association */
        /*	to object containing defn. */
        public const int SYMINFO_FLG_PASSTHRU = 0x0002;    /* ignored - see SYMINFO_FLG_FILTER */
        public const int SYMINFO_FLG_COPY = 0x0004;    /* symbol is a copy-reloc */
        public const int SYMINFO_FLG_LAZYLOAD = 0x0008;    /* object containing defn should be */
        /*	lazily-loaded */
        public const int SYMINFO_FLG_DIRECTBIND = 0x0010;  /* ref should be bound directly to */
        /*	object containing defn. */
        public const int SYMINFO_FLG_NOEXTDIRECT = 0x0020; /* don't let an external reference */
        /*	directly bind to this symbol */
        public const int SYMINFO_FLG_FILTER = 0x0002;  /* symbol ref is associated to a */
        public const int SYMINFO_FLG_AUXILIARY = 0x0040;   /* 	standard or auxiliary filter */

        /*
         * Syminfo.si_boundto values.
         */
        public const int SYMINFO_BT_SELF = 0xffff; /* symbol bound to self */
        public const int SYMINFO_BT_PARENT = 0xfffe;   /* symbol bound to parent */
        public const int SYMINFO_BT_NONE = 0xfffd; /* no special symbol binding */
        public const int SYMINFO_BT_EXTERN = 0xfffc;   /* symbol defined as external */
        public const int SYMINFO_BT_LOWRESERVE = 0xff00;   /* beginning of reserved entries */

        /*
         * Syminfo version values.
         */
        public const int SYMINFO_NONE = 0; /* Syminfo version */
        public const int SYMINFO_CURRENT = 1;
        public const int SYMINFO_NUM = 2;

        /*
         * Relocation types.
         *
         * All machine architectures are defined here to allow tools on one to
         * handle others.
         */

        public const int R_386_NONE = 0;   /* No relocation. */
        public const int R_386_32 = 1; /* Add symbol value. */
        public const int R_386_PC32 = 2;   /* Add PC-relative symbol value. */
        public const int R_386_GOT32 = 3;  /* Add PC-relative GOT offset. */
        public const int R_386_PLT32 = 4;  /* Add PC-relative PLT offset. */
        public const int R_386_COPY = 5;   /* Copy data from shared object. */
        public const int R_386_GLOB_DAT = 6;   /* Set GOT entry to data address. */
        public const int R_386_JMP_SLOT = 7;   /* Set GOT entry to code address. */
        public const int R_386_RELATIVE = 8;   /* Add load address of shared object. */
        public const int R_386_GOTOFF = 9; /* Add GOT-relative symbol address. */
        public const int R_386_GOTPC = 10; /* Add PC-relative GOT table address. */
        public const int R_386_TLS_TPOFF = 14; /* Negative offset in static TLS block */
        public const int R_386_TLS_IE = 15;    /* Absolute address of GOT for -ve static TLS */
        public const int R_386_TLS_GOTIE = 16; /* GOT entry for negative static TLS block */
        public const int R_386_TLS_LE = 17;    /* Negative offset relative to static TLS */
        public const int R_386_TLS_GD = 18;    /* 32 bit offset to GOT (index,off) pair */
        public const int R_386_TLS_LDM = 19;   /* 32 bit offset to GOT (index,zero) pair */
        public const int R_386_TLS_GD_32 = 24; /* 32 bit offset to GOT (index,off) pair */
        public const int R_386_TLS_GD_PUSH = 25;   /* pushl instruction for Sun ABI GD sequence */
        public const int R_386_TLS_GD_CALL = 26;   /* call instruction for Sun ABI GD sequence */
        public const int R_386_TLS_GD_POP = 27;    /* popl instruction for Sun ABI GD sequence */
        public const int R_386_TLS_LDM_32 = 28;    /* 32 bit offset to GOT (index,zero) pair */
        public const int R_386_TLS_LDM_PUSH = 29;  /* pushl instruction for Sun ABI LD sequence */
        public const int R_386_TLS_LDM_CALL = 30;  /* call instruction for Sun ABI LD sequence */
        public const int R_386_TLS_LDM_POP = 31;   /* popl instruction for Sun ABI LD sequence */
        public const int R_386_TLS_LDO_32 = 32;    /* 32 bit offset from start of TLS block */
        public const int R_386_TLS_IE_32 = 33; /* 32 bit offset to GOT static TLS offset entry */
        public const int R_386_TLS_LE_32 = 34; /* 32 bit offset within static TLS block */
        public const int R_386_TLS_DTPMOD32 = 35;  /* GOT entry containing TLS index */
        public const int R_386_TLS_DTPOFF32 = 36;  /* GOT entry containing TLS offset */
        public const int R_386_TLS_TPOFF32 = 37;   /* GOT entry of -ve static TLS offset */
        public const int R_386_IRELATIVE = 42; /* PLT entry resolved indirectly at runtime */

        public const int R_ARM_NONE = 0;   /* No relocation. */
        public const int R_ARM_PC24 = 1;
        public const int R_ARM_ABS32 = 2;
        public const int R_ARM_REL32 = 3;
        public const int R_ARM_PC13 = 4;
        public const int R_ARM_ABS16 = 5;
        public const int R_ARM_ABS12 = 6;
        public const int R_ARM_THM_ABS5 = 7;
        public const int R_ARM_ABS8 = 8;
        public const int R_ARM_SBREL32 = 9;
        public const int R_ARM_THM_PC22 = 10;
        public const int R_ARM_THM_PC8 = 11;
        public const int R_ARM_AMP_VCALL9 = 12;
        public const int R_ARM_SWI24 = 13;
        public const int R_ARM_THM_SWI8 = 14;
        public const int R_ARM_XPC25 = 15;
        public const int R_ARM_THM_XPC22 = 16;
        /* TLS relocations */
        public const int R_ARM_TLS_DTPMOD32 = 17;  /* ID of module containing symbol */
        public const int R_ARM_TLS_DTPOFF32 = 18;  /* Offset in TLS block */
        public const int R_ARM_TLS_TPOFF32 = 19;   /* Offset in static TLS block */
        public const int R_ARM_COPY = 20;  /* Copy data from shared object. */
        public const int R_ARM_GLOB_DAT = 21;  /* Set GOT entry to data address. */
        public const int R_ARM_JUMP_SLOT = 22; /* Set GOT entry to code address. */
        public const int R_ARM_RELATIVE = 23;  /* Add load address of shared object. */
        public const int R_ARM_GOTOFF = 24;    /* Add GOT-relative symbol address. */
        public const int R_ARM_GOTPC = 25; /* Add PC-relative GOT table address. */
        public const int R_ARM_GOT32 = 26; /* Add PC-relative GOT offset. */
        public const int R_ARM_PLT32 = 27; /* Add PC-relative PLT offset. */
        public const int R_ARM_GNU_VTENTRY = 100;
        public const int R_ARM_GNU_VTINHERIT = 101;
        public const int R_ARM_RSBREL32 = 250;
        public const int R_ARM_THM_RPC22 = 251;
        public const int R_ARM_RREL32 = 252;
        public const int R_ARM_RABS32 = 253;
        public const int R_ARM_RPC24 = 254;
        public const int R_ARM_RBASE = 255;

        /*	Name			Value	   Field	Calculation */
        public const int R_IA_64_NONE = 0; /* None */
        public const int R_IA_64_IMM14 = 0x21; /* immediate14	S + A */
        public const int R_IA_64_IMM22 = 0x22; /* immediate22	S + A */
        public const int R_IA_64_IMM64 = 0x23; /* immediate64	S + A */
        public const int R_IA_64_DIR32MSB = 0x24;  /* word32 MSB	S + A */
        public const int R_IA_64_DIR32LSB = 0x25;  /* word32 LSB	S + A */
        public const int R_IA_64_DIR64MSB = 0x26;  /* word64 MSB	S + A */
        public const int R_IA_64_DIR64LSB = 0x27;  /* word64 LSB	S + A */
        public const int R_IA_64_GPREL22 = 0x2a;   /* immediate22	@gprel(S + A) */
        public const int R_IA_64_GPREL64I = 0x2b;  /* immediate64	@gprel(S + A) */
        public const int R_IA_64_GPREL32MSB = 0x2c;    /* word32 MSB	@gprel(S + A) */
        public const int R_IA_64_GPREL32LSB = 0x2d;    /* word32 LSB	@gprel(S + A) */
        public const int R_IA_64_GPREL64MSB = 0x2e;    /* word64 MSB	@gprel(S + A) */
        public const int R_IA_64_GPREL64LSB = 0x2f;    /* word64 LSB	@gprel(S + A) */
        public const int R_IA_64_LTOFF22 = 0x32;   /* immediate22	@ltoff(S + A) */
        public const int R_IA_64_LTOFF64I = 0x33;  /* immediate64	@ltoff(S + A) */
        public const int R_IA_64_PLTOFF22 = 0x3a;  /* immediate22	@pltoff(S + A) */
        public const int R_IA_64_PLTOFF64I = 0x3b; /* immediate64	@pltoff(S + A) */
        public const int R_IA_64_PLTOFF64MSB = 0x3e;   /* word64 MSB	@pltoff(S + A) */
        public const int R_IA_64_PLTOFF64LSB = 0x3f;   /* word64 LSB	@pltoff(S + A) */
        public const int R_IA_64_FPTR64I = 0x43;   /* immediate64	@fptr(S + A) */
        public const int R_IA_64_FPTR32MSB = 0x44; /* word32 MSB	@fptr(S + A) */
        public const int R_IA_64_FPTR32LSB = 0x45; /* word32 LSB	@fptr(S + A) */
        public const int R_IA_64_FPTR64MSB = 0x46; /* word64 MSB	@fptr(S + A) */
        public const int R_IA_64_FPTR64LSB = 0x47; /* word64 LSB	@fptr(S + A) */
        public const int R_IA_64_PCREL60B = 0x48;  /* immediate60 form1 S + A - P */
        public const int R_IA_64_PCREL21B = 0x49;  /* immediate21 form1 S + A - P */
        public const int R_IA_64_PCREL21M = 0x4a;  /* immediate21 form2 S + A - P */
        public const int R_IA_64_PCREL21F = 0x4b;  /* immediate21 form3 S + A - P */
        public const int R_IA_64_PCREL32MSB = 0x4c;    /* word32 MSB	S + A - P */
        public const int R_IA_64_PCREL32LSB = 0x4d;    /* word32 LSB	S + A - P */
        public const int R_IA_64_PCREL64MSB = 0x4e;    /* word64 MSB	S + A - P */
        public const int R_IA_64_PCREL64LSB = 0x4f;    /* word64 LSB	S + A - P */
        public const int R_IA_64_LTOFF_FPTR22 = 0x52;  /* immediate22	@ltoff(@fptr(S + A)) */
        public const int R_IA_64_LTOFF_FPTR64I = 0x53; /* immediate64	@ltoff(@fptr(S + A)) */
        public const int R_IA_64_LTOFF_FPTR32MSB = 0x54;   /* word32 MSB	@ltoff(@fptr(S + A)) */
        public const int R_IA_64_LTOFF_FPTR32LSB = 0x55;   /* word32 LSB	@ltoff(@fptr(S + A)) */
        public const int R_IA_64_LTOFF_FPTR64MSB = 0x56;   /* word64 MSB	@ltoff(@fptr(S + A)) */
        public const int R_IA_64_LTOFF_FPTR64LSB = 0x57;   /* word64 LSB	@ltoff(@fptr(S + A)) */
        public const int R_IA_64_SEGREL32MSB = 0x5c;   /* word32 MSB	@segrel(S + A) */
        public const int R_IA_64_SEGREL32LSB = 0x5d;   /* word32 LSB	@segrel(S + A) */
        public const int R_IA_64_SEGREL64MSB = 0x5e;   /* word64 MSB	@segrel(S + A) */
        public const int R_IA_64_SEGREL64LSB = 0x5f;   /* word64 LSB	@segrel(S + A) */
        public const int R_IA_64_SECREL32MSB = 0x64;   /* word32 MSB	@secrel(S + A) */
        public const int R_IA_64_SECREL32LSB = 0x65;   /* word32 LSB	@secrel(S + A) */
        public const int R_IA_64_SECREL64MSB = 0x66;   /* word64 MSB	@secrel(S + A) */
        public const int R_IA_64_SECREL64LSB = 0x67;   /* word64 LSB	@secrel(S + A) */
        public const int R_IA_64_REL32MSB = 0x6c;  /* word32 MSB	BD + A */
        public const int R_IA_64_REL32LSB = 0x6d;  /* word32 LSB	BD + A */
        public const int R_IA_64_REL64MSB = 0x6e;  /* word64 MSB	BD + A */
        public const int R_IA_64_REL64LSB = 0x6f;  /* word64 LSB	BD + A */
        public const int R_IA_64_LTV32MSB = 0x74;  /* word32 MSB	S + A */
        public const int R_IA_64_LTV32LSB = 0x75;  /* word32 LSB	S + A */
        public const int R_IA_64_LTV64MSB = 0x76;  /* word64 MSB	S + A */
        public const int R_IA_64_LTV64LSB = 0x77;  /* word64 LSB	S + A */
        public const int R_IA_64_PCREL21BI = 0x79; /* immediate21 form1 S + A - P */
        public const int R_IA_64_PCREL22 = 0x7a;   /* immediate22	S + A - P */
        public const int R_IA_64_PCREL64I = 0x7b;  /* immediate64	S + A - P */
        public const int R_IA_64_IPLTMSB = 0x80;   /* function descriptor MSB special */
        public const int R_IA_64_IPLTLSB = 0x81;   /* function descriptor LSB speciaal */
        public const int R_IA_64_SUB = 0x85;   /* immediate64	A - S */
        public const int R_IA_64_LTOFF22X = 0x86;  /* immediate22	special */
        public const int R_IA_64_LDXMOV = 0x87;    /* immediate22	special */
        public const int R_IA_64_TPREL14 = 0x91;   /* imm14	@tprel(S + A) */
        public const int R_IA_64_TPREL22 = 0x92;   /* imm22	@tprel(S + A) */
        public const int R_IA_64_TPREL64I = 0x93;  /* imm64	@tprel(S + A) */
        public const int R_IA_64_TPREL64MSB = 0x96;    /* word64 MSB	@tprel(S + A) */
        public const int R_IA_64_TPREL64LSB = 0x97;    /* word64 LSB	@tprel(S + A) */
        public const int R_IA_64_LTOFF_TPREL22 = 0x9a; /* imm22	@ltoff(@tprel(S+A)) */
        public const int R_IA_64_DTPMOD64MSB = 0xa6;   /* word64 MSB	@dtpmod(S + A) */
        public const int R_IA_64_DTPMOD64LSB = 0xa7;   /* word64 LSB	@dtpmod(S + A) */
        public const int R_IA_64_LTOFF_DTPMOD22 = 0xaa;    /* imm22	@ltoff(@dtpmod(S+A)) */
        public const int R_IA_64_DTPREL14 = 0xb1;  /* imm14	@dtprel(S + A) */
        public const int R_IA_64_DTPREL22 = 0xb2;  /* imm22	@dtprel(S + A) */
        public const int R_IA_64_DTPREL64I = 0xb3; /* imm64	@dtprel(S + A) */
        public const int R_IA_64_DTPREL32MSB = 0xb4;   /* word32 MSB	@dtprel(S + A) */
        public const int R_IA_64_DTPREL32LSB = 0xb5;   /* word32 LSB	@dtprel(S + A) */
        public const int R_IA_64_DTPREL64MSB = 0xb6;   /* word64 MSB	@dtprel(S + A) */
        public const int R_IA_64_DTPREL64LSB = 0xb7;   /* word64 LSB	@dtprel(S + A) */
        public const int R_IA_64_LTOFF_DTPREL22 = 0xba;    /* imm22	@ltoff(@dtprel(S+A)) */

        public const int R_MIPS_NONE = 0;  /* No reloc */
        public const int R_MIPS_16 = 1;    /* Direct 16 bit */
        public const int R_MIPS_32 = 2;    /* Direct 32 bit */
        public const int R_MIPS_REL32 = 3; /* PC relative 32 bit */
        public const int R_MIPS_26 = 4;    /* Direct 26 bit shifted */
        public const int R_MIPS_HI16 = 5;  /* High 16 bit */
        public const int R_MIPS_LO16 = 6;  /* Low 16 bit */
        public const int R_MIPS_GPREL16 = 7;   /* GP relative 16 bit */
        public const int R_MIPS_LITERAL = 8;   /* 16 bit literal entry */
        public const int R_MIPS_GOT16 = 9; /* 16 bit GOT entry */
        public const int R_MIPS_PC16 = 10; /* PC relative 16 bit */
        public const int R_MIPS_CALL16 = 11;   /* 16 bit GOT entry for function */
        public const int R_MIPS_GPREL32 = 12;  /* GP relative 32 bit */
        public const int R_MIPS_64 = 18;   /* Direct 64 bit */
        public const int R_MIPS_GOTHI16 = 21;  /* GOT HI 16 bit */
        public const int R_MIPS_GOTLO16 = 22;  /* GOT LO 16 bit */
        public const int R_MIPS_CALLHI16 = 30; /* upper 16 bit GOT entry for function */
        public const int R_MIPS_CALLLO16 = 31; /* lower 16 bit GOT entry for function */

        public const int R_PPC_NONE = 0;   /* No relocation. */
        public const int R_PPC_ADDR32 = 1;
        public const int R_PPC_ADDR24 = 2;
        public const int R_PPC_ADDR16 = 3;
        public const int R_PPC_ADDR16_LO = 4;
        public const int R_PPC_ADDR16_HI = 5;
        public const int R_PPC_ADDR16_HA = 6;
        public const int R_PPC_ADDR14 = 7;
        public const int R_PPC_ADDR14_BRTAKEN = 8;
        public const int R_PPC_ADDR14_BRNTAKEN = 9;
        public const int R_PPC_REL24 = 10;
        public const int R_PPC_REL14 = 11;
        public const int R_PPC_REL14_BRTAKEN = 12;
        public const int R_PPC_REL14_BRNTAKEN = 13;
        public const int R_PPC_GOT16 = 14;
        public const int R_PPC_GOT16_LO = 15;
        public const int R_PPC_GOT16_HI = 16;
        public const int R_PPC_GOT16_HA = 17;
        public const int R_PPC_PLTREL24 = 18;
        public const int R_PPC_COPY = 19;
        public const int R_PPC_GLOB_DAT = 20;
        public const int R_PPC_JMP_SLOT = 21;
        public const int R_PPC_RELATIVE = 22;
        public const int R_PPC_LOCAL24PC = 23;
        public const int R_PPC_UADDR32 = 24;
        public const int R_PPC_UADDR16 = 25;
        public const int R_PPC_REL32 = 26;
        public const int R_PPC_PLT32 = 27;
        public const int R_PPC_PLTREL32 = 28;
        public const int R_PPC_PLT16_LO = 29;
        public const int R_PPC_PLT16_HI = 30;
        public const int R_PPC_PLT16_HA = 31;
        public const int R_PPC_SDAREL16 = 32;
        public const int R_PPC_SECTOFF = 33;
        public const int R_PPC_SECTOFF_LO = 34;
        public const int R_PPC_SECTOFF_HI = 35;
        public const int R_PPC_SECTOFF_HA = 36;

        /*
         * 64-bit relocations
         */
        public const int R_PPC64_ADDR64 = 38;
        public const int R_PPC64_ADDR16_HIGHER = 39;
        public const int R_PPC64_ADDR16_HIGHERA = 40;
        public const int R_PPC64_ADDR16_HIGHEST = 41;
        public const int R_PPC64_ADDR16_HIGHESTA = 42;
        public const int R_PPC64_UADDR64 = 43;
        public const int R_PPC64_REL64 = 44;
        public const int R_PPC64_PLT64 = 45;
        public const int R_PPC64_PLTREL64 = 46;
        public const int R_PPC64_TOC16 = 47;
        public const int R_PPC64_TOC16_LO = 48;
        public const int R_PPC64_TOC16_HI = 49;
        public const int R_PPC64_TOC16_HA = 50;
        public const int R_PPC64_TOC = 51;
        public const int R_PPC64_DTPMOD64 = 68;
        public const int R_PPC64_TPREL64 = 73;
        public const int R_PPC64_DTPREL64 = 78;

        /*
         * TLS relocations
         */
        public const int R_PPC_TLS = 67;
        public const int R_PPC_DTPMOD32 = 68;
        public const int R_PPC_TPREL16 = 69;
        public const int R_PPC_TPREL16_LO = 70;
        public const int R_PPC_TPREL16_HI = 71;
        public const int R_PPC_TPREL16_HA = 72;
        public const int R_PPC_TPREL32 = 73;
        public const int R_PPC_DTPREL16 = 74;
        public const int R_PPC_DTPREL16_LO = 75;
        public const int R_PPC_DTPREL16_HI = 76;
        public const int R_PPC_DTPREL16_HA = 77;
        public const int R_PPC_DTPREL32 = 78;
        public const int R_PPC_GOT_TLSGD16 = 79;
        public const int R_PPC_GOT_TLSGD16_LO = 80;
        public const int R_PPC_GOT_TLSGD16_HI = 81;
        public const int R_PPC_GOT_TLSGD16_HA = 82;
        public const int R_PPC_GOT_TLSLD16 = 83;
        public const int R_PPC_GOT_TLSLD16_LO = 84;
        public const int R_PPC_GOT_TLSLD16_HI = 85;
        public const int R_PPC_GOT_TLSLD16_HA = 86;
        public const int R_PPC_GOT_TPREL16 = 87;
        public const int R_PPC_GOT_TPREL16_LO = 88;
        public const int R_PPC_GOT_TPREL16_HI = 89;
        public const int R_PPC_GOT_TPREL16_HA = 90;

        /*
         * The remaining relocs are from the Embedded ELF ABI, and are not in the
         *  SVR4 ELF ABI.
         */

        public const int R_PPC_EMB_NADDR32 = 101;
        public const int R_PPC_EMB_NADDR16 = 102;
        public const int R_PPC_EMB_NADDR16_LO = 103;
        public const int R_PPC_EMB_NADDR16_HI = 104;
        public const int R_PPC_EMB_NADDR16_HA = 105;
        public const int R_PPC_EMB_SDAI16 = 106;
        public const int R_PPC_EMB_SDA2I16 = 107;
        public const int R_PPC_EMB_SDA2REL = 108;
        public const int R_PPC_EMB_SDA21 = 109;
        public const int R_PPC_EMB_MRKREF = 110;
        public const int R_PPC_EMB_RELSEC16 = 111;
        public const int R_PPC_EMB_RELST_LO = 112;
        public const int R_PPC_EMB_RELST_HI = 113;
        public const int R_PPC_EMB_RELST_HA = 114;
        public const int R_PPC_EMB_BIT_FLD = 115;
        public const int R_PPC_EMB_RELSDA = 116;

        public const int R_SPARC_NONE = 0;
        public const int R_SPARC_8 = 1;
        public const int R_SPARC_16 = 2;
        public const int R_SPARC_32 = 3;
        public const int R_SPARC_DISP8 = 4;
        public const int R_SPARC_DISP16 = 5;
        public const int R_SPARC_DISP32 = 6;
        public const int R_SPARC_WDISP30 = 7;
        public const int R_SPARC_WDISP22 = 8;
        public const int R_SPARC_HI22 = 9;
        public const int R_SPARC_22 = 10;
        public const int R_SPARC_13 = 11;
        public const int R_SPARC_LO10 = 12;
        public const int R_SPARC_GOT10 = 13;
        public const int R_SPARC_GOT13 = 14;
        public const int R_SPARC_GOT22 = 15;
        public const int R_SPARC_PC10 = 16;
        public const int R_SPARC_PC22 = 17;
        public const int R_SPARC_WPLT30 = 18;
        public const int R_SPARC_COPY = 19;
        public const int R_SPARC_GLOB_DAT = 20;
        public const int R_SPARC_JMP_SLOT = 21;
        public const int R_SPARC_RELATIVE = 22;
        public const int R_SPARC_UA32 = 23;
        public const int R_SPARC_PLT32 = 24;
        public const int R_SPARC_HIPLT22 = 25;
        public const int R_SPARC_LOPLT10 = 26;
        public const int R_SPARC_PCPLT32 = 27;
        public const int R_SPARC_PCPLT22 = 28;
        public const int R_SPARC_PCPLT10 = 29;
        public const int R_SPARC_10 = 30;
        public const int R_SPARC_11 = 31;
        public const int R_SPARC_64 = 32;
        public const int R_SPARC_OLO10 = 33;
        public const int R_SPARC_HH22 = 34;
        public const int R_SPARC_HM10 = 35;
        public const int R_SPARC_LM22 = 36;
        public const int R_SPARC_PC_HH22 = 37;
        public const int R_SPARC_PC_HM10 = 38;
        public const int R_SPARC_PC_LM22 = 39;
        public const int R_SPARC_WDISP16 = 40;
        public const int R_SPARC_WDISP19 = 41;
        public const int R_SPARC_GLOB_JMP = 42;
        public const int R_SPARC_7 = 43;
        public const int R_SPARC_5 = 44;
        public const int R_SPARC_6 = 45;
        public const int R_SPARC_DISP64 = 46;
        public const int R_SPARC_PLT64 = 47;
        public const int R_SPARC_HIX22 = 48;
        public const int R_SPARC_LOX10 = 49;
        public const int R_SPARC_H44 = 50;
        public const int R_SPARC_M44 = 51;
        public const int R_SPARC_L44 = 52;
        public const int R_SPARC_REGISTER = 53;
        public const int R_SPARC_UA64 = 54;
        public const int R_SPARC_UA16 = 55;
        public const int R_SPARC_TLS_GD_HI22 = 56;
        public const int R_SPARC_TLS_GD_LO10 = 57;
        public const int R_SPARC_TLS_GD_ADD = 58;
        public const int R_SPARC_TLS_GD_CALL = 59;
        public const int R_SPARC_TLS_LDM_HI22 = 60;
        public const int R_SPARC_TLS_LDM_LO10 = 61;
        public const int R_SPARC_TLS_LDM_ADD = 62;
        public const int R_SPARC_TLS_LDM_CALL = 63;
        public const int R_SPARC_TLS_LDO_HIX22 = 64;
        public const int R_SPARC_TLS_LDO_LOX10 = 65;
        public const int R_SPARC_TLS_LDO_ADD = 66;
        public const int R_SPARC_TLS_IE_HI22 = 67;
        public const int R_SPARC_TLS_IE_LO10 = 68;
        public const int R_SPARC_TLS_IE_LD = 69;
        public const int R_SPARC_TLS_IE_LDX = 70;
        public const int R_SPARC_TLS_IE_ADD = 71;
        public const int R_SPARC_TLS_LE_HIX22 = 72;
        public const int R_SPARC_TLS_LE_LOX10 = 73;
        public const int R_SPARC_TLS_DTPMOD32 = 74;
        public const int R_SPARC_TLS_DTPMOD64 = 75;
        public const int R_SPARC_TLS_DTPOFF32 = 76;
        public const int R_SPARC_TLS_DTPOFF64 = 77;
        public const int R_SPARC_TLS_TPOFF32 = 78;
        public const int R_SPARC_TLS_TPOFF64 = 79;

        public const int R_X86_64_NONE = 0;    /* No relocation. */
        public const int R_X86_64_64 = 1;  /* Add 64 bit symbol value. */
        public const int R_X86_64_PC32 = 2;    /* PC-relative 32 bit signed sym value. */
        public const int R_X86_64_GOT32 = 3;   /* PC-relative 32 bit GOT offset. */
        public const int R_X86_64_PLT32 = 4;   /* PC-relative 32 bit PLT offset. */
        public const int R_X86_64_COPY = 5;    /* Copy data from shared object. */
        public const int R_X86_64_GLOB_DAT = 6;    /* Set GOT entry to data address. */
        public const int R_X86_64_JMP_SLOT = 7;    /* Set GOT entry to code address. */
        public const int R_X86_64_RELATIVE = 8;    /* Add load address of shared object. */
        public const int R_X86_64_GOTPCREL = 9;    /* Add 32 bit signed pcrel offset to GOT. */
        public const int R_X86_64_32 = 10; /* Add 32 bit zero extended symbol value */
        public const int R_X86_64_32S = 11;    /* Add 32 bit sign extended symbol value */
        public const int R_X86_64_16 = 12; /* Add 16 bit zero extended symbol value */
        public const int R_X86_64_PC16 = 13;   /* Add 16 bit signed extended pc relative symbol value */
        public const int R_X86_64_8 = 14;  /* Add 8 bit zero extended symbol value */
        public const int R_X86_64_PC8 = 15;    /* Add 8 bit signed extended pc relative symbol value */
        public const int R_X86_64_DTPMOD64 = 16;   /* ID of module containing symbol */
        public const int R_X86_64_DTPOFF64 = 17;   /* Offset in TLS block */
        public const int R_X86_64_TPOFF64 = 18;    /* Offset in static TLS block */
        public const int R_X86_64_TLSGD = 19;  /* PC relative offset to GD GOT entry */
        public const int R_X86_64_TLSLD = 20;  /* PC relative offset to LD GOT entry */
        public const int R_X86_64_DTPOFF32 = 21;   /* Offset in TLS block */
        public const int R_X86_64_GOTTPOFF = 22;   /* PC relative offset to IE GOT entry */
        public const int R_X86_64_TPOFF32 = 23;    /* Offset in static TLS block */
        public const int R_X86_64_IRELATIVE = 37;

        public const int NT_GNU_BUILD_ID = 3;   /* Note type for .note.gnu.build-id */

        /* Dynamic relocations */
        public const int R_AARCH64_COPY = 1024;
        public const int R_AARCH64_GLOB_DAT = 1025;    /* Create GOT entry.  */
        public const int R_AARCH64_JUMP_SLOT = 1026;    /* Create PLT entry.  */
        public const int R_AARCH64_RELATIVE = 1027;    /* Adjust by program base.  */
        public const int R_AARCH64_TLS_TPREL64 = 1030;
        public const int R_AARCH64_TLS_DTPREL32 = 1031;
        public const int R_AARCH64_IRELATIVE = 1032;
    }
}
