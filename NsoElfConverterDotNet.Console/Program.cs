using System;
using System.IO;

namespace NsoElfConverterDotNet.ConsoleApp
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length < 2)
            {
                Console.WriteLine("Usage:");
                Console.WriteLine("NsoElfConverterDotNet <main> <main.elf>");
                Console.WriteLine("or");
                Console.WriteLine("NsoElfConverterDotNet <main.elf> <main>");
                return;
            }

            if (!File.Exists(args[0]))
            {
                Console.WriteLine("Input file not found");
                return;
            }

            INsoElfConverter converter = NsoElfConverter.Instance;

            if (!Path.GetExtension(args[0]).TrimStart('.').Equals("elf", StringComparison.OrdinalIgnoreCase))
            {
                // NSO to ELF
                File.WriteAllBytes(args[1], converter.ConvertNsoToElf(File.ReadAllBytes(args[0])));
            }
            else
            {
                // ELF to NSO
                File.WriteAllBytes(args[1], converter.ConvertElfToNso(File.ReadAllBytes(args[0])));
            }            
        }
    }
}
