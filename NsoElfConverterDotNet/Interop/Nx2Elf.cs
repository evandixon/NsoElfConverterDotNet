using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;

namespace NsoElfConverterDotNet.Interop
{
    internal static class Nx2ElfInterop
    {
        private const string nx2elf_linux_x64 = "libnx2elf_x64.so";
        private const string nx2elf_linux_x86 = "libnx2elf_x86.so";
        private const string nx2elf_win_x64 = "nx2elf_win_x64.dll";
        private const string nx2elf_win_x86 = "nx2elf_win_x86.dll";

        static Nx2ElfInterop()
        {
            var path = Path.GetDirectoryName(typeof(Nx2ElfInterop).Assembly.Location);

            var linuxX64Path = Path.Combine(path, nx2elf_linux_x64);
            if (!File.Exists(linuxX64Path))
            {
                File.WriteAllBytes(linuxX64Path, Properties.Resources.libnx2elf_x64);
            }

            var linuxX86Path = Path.Combine(path, nx2elf_linux_x86);
            if (!File.Exists(linuxX86Path))
            {
                File.WriteAllBytes(linuxX86Path, Properties.Resources.libnx2elf_x86);
            }

            var windowsX64Path = Path.Combine(path, nx2elf_win_x64);
            if (!File.Exists(windowsX64Path))
            {
                File.WriteAllBytes(windowsX64Path, Properties.Resources.nx2elf_x64);
            }

            var windowsX86Path = Path.Combine(path, nx2elf_win_x86);
            if (!File.Exists(windowsX86Path))
            {
                File.WriteAllBytes(windowsX86Path, Properties.Resources.nx2elf_x86);
            }
        }

        [DllImport(nx2elf_win_x86, EntryPoint = "NsoToElf")]
        private static extern bool WindowsNsoToElfX86(string path, string elf_file);

        [DllImport(nx2elf_win_x64, EntryPoint = "NsoToElf")]
        private static extern bool WindowsNsoToElfX64(string path, string elf_file);

        [DllImport(nx2elf_linux_x86, EntryPoint = "NsoToElf")]
        private static extern bool LinuxNsoToElfX86(string path, string elf_file);

        [DllImport(nx2elf_linux_x64, EntryPoint = "NsoToElf")]
        private static extern bool LinuxNsoToElfX64(string path, string elf_file);

        public static bool NsoToElf(string path, string elf_file)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                if (Environment.Is64BitOperatingSystem)
                {
                    return WindowsNsoToElfX64(path, elf_file);
                }
                else
                {
                    return WindowsNsoToElfX86(path, elf_file);
                }
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                if (Environment.Is64BitOperatingSystem)
                {
                    return LinuxNsoToElfX64(path, elf_file);
                }
                else
                {
                    return WindowsNsoToElfX86(path, elf_file);
                }
            }
            else
            {
                throw new PlatformNotSupportedException("Only Windows and Linux are supported.");
            }
        }
    }
}
