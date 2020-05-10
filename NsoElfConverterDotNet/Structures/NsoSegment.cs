using System;
using System.Buffers.Binary;

namespace NsoElfConverterDotNet.Structures
{
    public struct NsoSegment
    {
        public const int Length = 16;

        public NsoSegment(ReadOnlySpan<byte> data)
        {
            FileOffset = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(0, 4));
            MemoryOffset = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(4, 4));
            MemorySize = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(8, 4));
            AlignOrTotalSz = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(12, 4));
        }

        public uint FileOffset { get; set; }
        public uint MemoryOffset { get; set; }
        public uint MemorySize { get; set; }
        public uint AlignOrTotalSz { get; set; }

        public byte[] ToByteArray()
        {
            var buffer = new byte[0x10];
            BitConverter.GetBytes(FileOffset).CopyTo(buffer, 0);
            BitConverter.GetBytes(MemoryOffset).CopyTo(buffer, 4);
            BitConverter.GetBytes(MemorySize).CopyTo(buffer, 8);
            BitConverter.GetBytes(AlignOrTotalSz).CopyTo(buffer, 12);
            return buffer;
        }
    }
}
