using NsoElfConverterDotNet.Elf2Nso;
using NsoElfConverterDotNet.Interop;
using SkyEditor.IO.Binary;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace NsoElfConverterDotNet
{
    public interface INsoElfConverter
    {
        /// <summary>
        /// Converts an NSO file to an ELF file
        /// </summary>
        /// <param name="nsoFilename">Path of the source NSO file</param>
        /// <param name="elfFilename">Path of the target ELF file</param>
        void ConvertNsoToElf(string nsoFilename, string elfFilename);

        /// <summary>
        /// Converts an NSO file to an ELF file
        /// </summary>
        /// <param name="nsoFilename">Path of the source NSO file</param>
        /// <returns>A byte array containing the contents of the target ELF file</returns>
        byte[] ConvertNsoToElf(string nsoFilename);

        /// <summary>
        /// Converts an NSO file to an ELF file
        /// </summary>
        /// <param name="nsoFile">Contents of the source NSO file</param>
        /// <returns>A byte array containing the contents of the target ELF file</returns>
        byte[] ConvertNsoToElf(byte[] nsoFile);

        /// <summary>
        /// Converts an ELF file to an NSO file
        /// </summary>
        /// <param name="elfFile">Contents of the source ELF file</param>
        /// <returns>A byte array containing the contents of the target NSO file</returns>
        byte[] ConvertElfToNso(byte[] elfFile);

        /// <summary>
        /// Converts an ELF file to an NSO file
        /// </summary>
        /// <param name="elfFile">Contents of the source ELF file</param>
        /// <returns>A byte array containing the contents of the target NSO file</returns>
        byte[] ConvertElfToNso(IReadOnlyBinaryDataAccessor elfFile);
    }

    public class NsoElfConverter : INsoElfConverter
    {
        public static readonly NsoElfConverter Instance = new NsoElfConverter();

        private NsoElfConverter()
        {
        }

        /// <summary>
        /// Converts an NSO file to an ELF file
        /// </summary>
        /// <param name="nsoFilename">Path of the source NSO file</param>
        /// <param name="elfFilename">Path of the target ELF file</param>
        public void ConvertNsoToElf(string nsoFilename, string elfFilename)
        {
            if (string.IsNullOrEmpty(nsoFilename))
            {
                throw new ArgumentNullException(nameof(nsoFilename));
            }
            if (string.IsNullOrEmpty(elfFilename))
            {
                throw new ArgumentNullException(nameof(elfFilename));
            }

            if (ArePathsEqual(nsoFilename, elfFilename))
            {
                throw new ArgumentException("Target path cannot be equal to the source path", nameof(elfFilename));
            }

            if (!File.Exists(nsoFilename))
            {
                throw new FileNotFoundException("Source file does not exist", nsoFilename);
            }

            Nx2Elf.NsoToElf(nsoFilename, elfFilename);

            if (!File.Exists(elfFilename))
            {
                throw new FileNotFoundException("Nx2Elf failed to create an ELF file.");
            }
        }

        /// <summary>
        /// Converts an NSO file to an ELF file
        /// </summary>
        /// <param name="nsoFilename">Path of the source NSO file</param>
        /// <returns>A byte array containing the contents of the target ELF file</returns>
        public byte[] ConvertNsoToElf(string nsoFilename)
        {
            var elfFilename = Path.GetTempFileName();
            try
            {
                ConvertNsoToElf(nsoFilename, elfFilename);
                return File.ReadAllBytes(elfFilename);
            }
            finally
            {
                File.Delete(elfFilename);
            }            
        }

        /// <summary>
        /// Converts an NSO file to an ELF file
        /// </summary>
        /// <param name="nsoFile">Contents of the source NSO file</param>
        /// <returns>A byte array containing the contents of the target ELF file</returns>
        public byte[] ConvertNsoToElf(byte[] nsoFile)
        {
            var nsoFilename = Path.GetTempFileName();
            var elfFilename = Path.GetTempFileName();
            try
            {
                File.WriteAllBytes(nsoFilename, nsoFile);
                ConvertNsoToElf(nsoFilename, elfFilename);
                return File.ReadAllBytes(elfFilename);
            }
            finally
            {
                File.Delete(nsoFilename);
                File.Delete(elfFilename);
            }
        }

        /// <summary>
        /// Converts an ELF file to an NSO file
        /// </summary>
        /// <param name="elfFile">Contents of the source ELF file</param>
        /// <returns>A byte array containing the contents of the target NSO file</returns>
        public byte[] ConvertElfToNso(byte[] elfFile)
        {
            using var binary = new BinaryFile(elfFile);
            return ElfToNsoConverter.ConvertElfToNso(binary);
        }

        /// <summary>
        /// Converts an ELF file to an NSO file
        /// </summary>
        /// <param name="elfFile">Contents of the source ELF file</param>
        /// <returns>A byte array containing the contents of the target NSO file</returns>
        public byte[] ConvertElfToNso(IReadOnlyBinaryDataAccessor elfFile)
        {
            return ElfToNsoConverter.ConvertElfToNso(elfFile);
        }

        private static bool ArePathsEqual(string pathA, string pathB)
        {
            var fullPathA = Path.GetFullPath(pathA);
            var fullPathB = Path.GetFullPath(pathB);

            return fullPathA.Equals(fullPathB, StringComparison.Ordinal);
        }
    }
}
