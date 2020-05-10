using NsoElfConverterDotNet.Elf2Nso;
using NsoElfConverterDotNet.Nx2elf;

namespace NsoElfConverterDotNet
{
    public interface INsoElfConverter
    {

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
        /// <param name="nsoFile">Contents of the source NSO file</param>
        /// <returns>A byte array containing the contents of the target ELF file</returns>
        public byte[] ConvertNsoToElf(byte[] nsoFile)
        {
            var nso = new NsoFile(nsoFile);
            return nso.ToElf();
        }

        /// <summary>
        /// Converts an ELF file to an NSO file
        /// </summary>
        /// <param name="elfFile">Contents of the source ELF file</param>
        /// <returns>A byte array containing the contents of the target NSO file</returns>
        public byte[] ConvertElfToNso(byte[] elfFile)
        {
            return ElfToNsoConverter.ConvertElfToNso(elfFile);
        }
    }
}
