using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;

namespace NsoElfConverterDotNet.Structures
{
    public struct DataExtent
    {
        public uint Offset { get; set; }
        public uint Size { get; set; }

        public static explicit operator ulong(DataExtent e)
        {
            var buffer = new byte[8];
            BinaryPrimitives.WriteUInt32LittleEndian(buffer, e.Offset);
            BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan().Slice(4), e.Size);
            return BinaryPrimitives.ReadUInt64LittleEndian(buffer);
        }

        public static explicit operator DataExtent(ulong l)
        {
            var buffer = new byte[8];
            BinaryPrimitives.WriteUInt64LittleEndian(buffer, l);
            var offset = BinaryPrimitives.ReadUInt32LittleEndian(buffer);
            var size = BinaryPrimitives.ReadUInt32LittleEndian(buffer.AsSpan().Slice(4));
            return new DataExtent 
            { 
                Offset = offset,
                Size = size
            };
        }
    }
}
