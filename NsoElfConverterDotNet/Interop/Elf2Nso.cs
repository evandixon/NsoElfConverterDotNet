using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace NsoElfConverterDotNet.Interop
{
    public static class Elf2Nso
    {
        private const string elf2nso = "elf2nso";
        private const string elf2nso1 = "elf2nso.exe";

        static Elf2Nso()
        {
            var path = Path.GetDirectoryName(typeof(Nx2Elf).Assembly.Location);

            var linuxPath = Path.Combine(path, elf2nso);
            if (!File.Exists(linuxPath))
            {
                File.WriteAllBytes(linuxPath, Properties.Resources.elf2nso);
            }

            var windowsPath = Path.Combine(path, elf2nso1);
            if (!File.Exists(windowsPath))
            {
                File.WriteAllBytes(windowsPath, Properties.Resources.elf2nso1);
            }
        }

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
