using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Text;

namespace NsoElfConverterDotNet.Structures
{
    public class NsoHeader
    {
        public const int Length = 0x10 + 0x30 + 0x20 + 12 + 0x24 + 16 + 3 * 0x20;

        public NsoHeader()
        {
            Magic = Encoding.ASCII.GetBytes("NSO0");
            Unk3 = 0x3f;
            Segments = new NsoSegment[3];
            BuildId = new byte[0x20];
            SegmentFileSizes = new uint[3];
            Padding = new byte[0x24];

            this.Hashes = new List<byte[]>
            {
                new byte[0x20],
                new byte[0x20],
                new byte[0x20]
            };
        }

        public NsoHeader(ReadOnlySpan<byte> data)
        {
            var index = 0;
            Magic = data.Slice(0, 4).ToArray(); index += 4;
            Unk1 = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(index)); index += 4;
            Unk2 = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(index)); index += 4;
            Unk3 = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(index)); index += 4;

            Segments = new NsoSegment[3];
            for (int i = 0; i < 3; i++)
            {
                Segments[i] = new NsoSegment(data.Slice(index, NsoSegment.Length)); index += NsoSegment.Length;
            }

            BuildId = data.Slice(index, 0x20).ToArray(); index += 0x20;

            SegmentFileSizes = new uint[3];
            for (int i = 0; i < 3; i++)
            {
                SegmentFileSizes[i] = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(index)); index += 4;
            }

            Padding = data.Slice(index, 0x24).ToArray(); index += 0x24;

            DynStr = (DataExtent)BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(index)); index += 8;
            DynSym = (DataExtent)BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(index)); index += 8;

            Hashes = new List<byte[]>(3);
            for (int i = 0; i < 3; i++)
            {
                Hashes.Add(data.Slice(index, 0x20).ToArray()); index += 0x20;
            }
        }

        public byte[] ToByteArray()
        {
            var buffer = new List<byte>(Length);
            buffer.AddRange(Magic);
            buffer.AddRange(BitConverter.GetBytes(Unk1));
            buffer.AddRange(BitConverter.GetBytes(Unk2));
            buffer.AddRange(BitConverter.GetBytes(Unk3));
            foreach (var segment in Segments)
            {
                buffer.AddRange(segment.ToByteArray());
            }
            buffer.AddRange(BuildId);
            foreach (var size in SegmentFileSizes)
            {
                buffer.AddRange(BitConverter.GetBytes(size));
            }
            buffer.AddRange(Padding);
            buffer.AddRange(BitConverter.GetBytes((ulong)DynStr));
            buffer.AddRange(BitConverter.GetBytes((ulong)DynSym));
            foreach (var hash in Hashes)
            {
                buffer.AddRange(hash);
            }
            return buffer.ToArray();
        }

        public byte[] Magic { get; } // Length: 4

        public uint Unk1 { get; set; }

        public uint Unk2 { get; set; }

        public uint Unk3 { get; set; }

        public NsoSegment[] Segments { get; set; } // Length: 3

        public byte[] BuildId { get; set; } // Length: 0x20

        public uint[] SegmentFileSizes { get; set; } // Length: 3

        public byte[] Padding { get; set; }

        public DataExtent DynStr { get; set; }

        public DataExtent DynSym { get; set; }

        public IList<byte[]> Hashes { get; set; } // 3 sets of byte[] length 0x20
    }
}
