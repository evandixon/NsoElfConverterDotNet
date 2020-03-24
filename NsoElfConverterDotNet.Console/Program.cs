using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace NsoElfConverterDotNet.ConsoleApp
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length < 2)
            {
                Console.WriteLine("Usage: NsoElfConverterDotNet <main> <main.elf>");
                return;
            }

            if (!File.Exists(args[0]))
            {
                Console.WriteLine("Input file not found");
                return;
            }

            Nx2Elf.NsoToElf(args[0], args[1]);
        }
    }
}
