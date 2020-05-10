using System;
using System.Buffers.Binary;

namespace NsoElfConverterDotNet.Structures.Elf
{
    /// <summary>
    /// Note header.  The ".note" section contains an array of notes.  Each
    /// begins with this header, aligned to a word boundary.  Immediately
    /// following the note header is n_namesz bytes of name, padded to the
    /// next word boundary.  Then comes n_descsz bytes of descriptor, again
    /// padded to a word boundary.  The values of n_namesz and n_descsz do
    /// not include the padding.
    /// </summary>
    public struct Elf64Nhdr
    {
        public const int Length = 12;

        public Elf64Nhdr(ReadOnlySpan<byte> data)
        {
            NameSize = BinaryPrimitives.ReadUInt32LittleEndian(data);
            DescriptorSize = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(4));
            Type = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(8));
        }

        /// <summary>
        /// Length of name
        /// </summary>
        public uint NameSize { get; set; }

        /// <summary>
        /// Length of descriptor
        /// </summary>
        public uint DescriptorSize { get; set; }

        /// <summary>
        /// Type of this note
        /// </summary>
        public uint Type { get; set; }
    }
}
