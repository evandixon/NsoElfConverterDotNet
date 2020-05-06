using SkyEditor.IO.Binary;
using System;
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
            SegmentFileSIzes = new uint[3];
            Padding = new byte[0x24];

            this.Hashes = new List<byte[]>
            {
                new byte[0x20],
                new byte[0x20],
                new byte[0x20]
            };
        }

        public NsoHeader(IReadOnlyBinaryDataAccessor accessor)
        {
            accessor.Position = 0;
            Magic = accessor.ReadNextArray(4);
            Unk1 = accessor.ReadNextUInt32();
            Unk2 = accessor.ReadNextUInt32();
            Unk3 = accessor.ReadNextUInt32();

            Segments = new NsoSegment[3];
            for (int i = 0; i < 3; i++)
            {
                Segments[i] = new NsoSegment(accessor.ReadNextSpan(NsoSegment.Length));
            }

            BuildId = accessor.ReadNextArray(0x20);

            SegmentFileSIzes = new uint[3];
            for (int i = 0; i < 3; i++)
            {
                SegmentFileSIzes[i] = accessor.ReadNextUInt32();
            }

            Padding = accessor.ReadNextArray(0x24);

            dynstr = (DataExtent)accessor.ReadNextUInt64();
            dynsym = (DataExtent)accessor.ReadNextUInt64();

            Hashes = new List<byte[]>(3);
            for (int i = 0; i < 3; i++)
            {
                Hashes[i] = accessor.ReadNextArray(0x20);
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
            foreach (var size in SegmentFileSIzes)
            {
                buffer.AddRange(BitConverter.GetBytes(size));
            }
            buffer.AddRange(Padding);
            buffer.AddRange(BitConverter.GetBytes((ulong)dynstr));
            buffer.AddRange(BitConverter.GetBytes((ulong)dynsym));
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

        public uint[] SegmentFileSIzes { get; set; } // Length: 3

        public byte[] Padding { get; set; }

        public DataExtent dynstr { get; set; }

        public DataExtent dynsym { get; set; }

        public IList<byte[]> Hashes { get; set; } // 3 sets of byte[] length 0x20
    }
}
