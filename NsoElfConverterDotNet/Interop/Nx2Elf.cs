using System;
using System.Collections.Generic;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;

namespace NsoElfConverterDotNet.Interop
{
    public static class Nx2Elf
    {
        const string DllFile = "nx2elf";

        static Nx2Elf()
        {
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
                        NativeLibrary.TryLoad("nx2elf-win-x64.dll", out libHandle);
                    }
                    else
                    {
                        NativeLibrary.TryLoad("nx2elf-win-x86.dll", out libHandle);
                    }
                }
                else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                {
                    if (Environment.Is64BitOperatingSystem)
                    {
                        NativeLibrary.TryLoad("nx2elf-linux-x64.so", out libHandle);
                    }
                    else
                    {
                        NativeLibrary.TryLoad("nx2elf-linux-x86.so", out libHandle);
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
