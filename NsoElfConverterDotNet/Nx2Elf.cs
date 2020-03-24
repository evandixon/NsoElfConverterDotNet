using System;
using System.Collections.Generic;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;

namespace NsoElfConverterDotNet
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
                else
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
            }
            return libHandle;
        }

        [DllImport(DllFile, EntryPoint = "NsoToElf")]
        public static extern bool NsoToElf(string path, string elf_file, bool verbose = false);

        //public static bool NsoToElf(string input, string output)
        //{
        //    IntPtr path = IntPtr.Zero;
        //    IntPtr elf_file = IntPtr.Zero;
        //    try
        //    {
        //        path = Marshal.StringToHGlobalUni(input);
        //        elf_file = Marshal.StringToHGlobalUni(output);

        //        return NsoToElf(path, elf_file, false);
        //    }
        //    finally
        //    {
        //        if (path != IntPtr.Zero)
        //        {
        //            Marshal.FreeHGlobal(path);
        //        }
        //        if (elf_file != IntPtr.Zero)
        //        {
        //            Marshal.FreeHGlobal(elf_file);
        //        }
        //    }
        //}
    }
}
