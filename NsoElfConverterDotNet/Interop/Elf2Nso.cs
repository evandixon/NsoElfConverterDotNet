using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace NsoElfConverterDotNet.Interop
{
    public static class Elf2Nso
    {
        public static void RunElf2Nso(string inputFile, string outputFile)
        {
            using var p = new Process();
            p.StartInfo.FileName = GetExecutableFilename();
            p.StartInfo.Arguments = $"\"{inputFile}\" \"{outputFile}\"";

            p.Start();
            p.WaitForExit();
        }

        private static string GetExecutableFilename()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                return "elf2nso.exe";
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                return "elf2nso";
            }
            else
            {
                throw new PlatformNotSupportedException("Only Windows and Linux are supported.");
            }
        }
    }
}
