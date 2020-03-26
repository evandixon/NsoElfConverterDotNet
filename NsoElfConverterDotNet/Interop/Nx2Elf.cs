using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;

namespace NsoElfConverterDotNet.Interop
{
    public static class Nx2Elf
    {
        private const string DllFile = "nx2elf";

        private const string nx2elf_linux_x64 = "nx2elf_linux_x64.so";
        private const string nx2elf_linux_x86 = "nx2elf_linux_x86.so";
        private const string nx2elf_win_x64 = "nx2elf_win_x64.dll";
        private const string nx2elf_win_x86 = "nx2elf_win_x86.dll";

        static Nx2Elf()
        {
            var path = Path.GetDirectoryName(typeof(Nx2Elf).Assembly.Location);

            var linuxX64Path = Path.Combine(path, nx2elf_linux_x64);
            if (!File.Exists(linuxX64Path))
            {
                File.WriteAllBytes(linuxX64Path, Properties.Resources.nx2elf_linux_x64);
            }

            var linuxX86Path = Path.Combine(path, nx2elf_linux_x86);
            if (!File.Exists(linuxX86Path))
            {
                File.WriteAllBytes(linuxX86Path, Properties.Resources.nx2elf_linux_x86);
            }

            var windowsX64Path = Path.Combine(path, nx2elf_win_x64);
            if (!File.Exists(windowsX64Path))
            {
                File.WriteAllBytes(windowsX64Path, Properties.Resources.nx2elf_win_x64);
            }

            var windowsX86Path = Path.Combine(path, nx2elf_win_x86);
            if (!File.Exists(windowsX86Path))
            {
                File.WriteAllBytes(windowsX86Path, Properties.Resources.nx2elf_win_x86);
            }

            NativeLibrary.SetDllImportResolver(typeof(Nx2Elf).Assembly, ImportResolver);
        }

        private static IntPtr ImportResolver(string libraryName, Assembly assembly, DllImportSearchPath? searchPath)
        {
            IntPtr libHandle = IntPtr.Zero;
            if (libraryName == DllFile)
            {
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    if (Environment.Is64BitOperatingSystem)
                    {
                        NativeLibrary.TryLoad(nx2elf_win_x64, out libHandle);
                    }
                    else
                    {
                        NativeLibrary.TryLoad(nx2elf_win_x86, out libHandle);
                    }
                }
                else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                {
                    if (Environment.Is64BitOperatingSystem)
                    {
                        NativeLibrary.TryLoad(nx2elf_linux_x64, out libHandle);
                    }
                    else
                    {
                        NativeLibrary.TryLoad(nx2elf_linux_x86, out libHandle);
                    }
                }
                else
                {
                    throw new PlatformNotSupportedException("Only Windows and Linux are supported.");
                }
            }
            return libHandle;
        }

        [DllImport(DllFile, EntryPoint = "NsoToElf")]
        public static extern bool NsoToElf(string path, string elf_file, bool verbose = false);
    }
}
