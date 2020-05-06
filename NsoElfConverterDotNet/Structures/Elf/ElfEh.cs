using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Text;

namespace NsoElfConverterDotNet.Structures.Elf
{
    public struct EhFrameHdr
    {
        public const int Length = 4;

        public EhFrameHdr(ReadOnlySpan<byte> data)
        {
            version = data[0];
            eh_frame_ptr_enc = data[1];
            fde_count_enc = data[2];
            table_enc = data[3];
        }

        public byte version { get; set; }
        public byte eh_frame_ptr_enc { get; set; }
        public byte fde_count_enc { get; set; }
        public byte table_enc { get; set; }
    };

    //struct EhCie
    //{
    //	public uintptr_t caf;
    //	public intptr_t daf;
    //	public u8 fde_enc;
    //	public const u8* insns;
    //	public size_t insns_len;
    //};
    //struct EhFde
    //{
    //	eh_cie cie;
    //	uintptr_t start;
    //	uintptr_t end;
    //	const u8* insns;
    //	size_t insns_len;
    //};
    //struct EhFdeRel
    //{
    //	u32 start;
    //	u32 end;
    //	uintptr_t caf;
    //	intptr_t daf;
    //	u32 init_insns;
    //	u32 init_insns_len;
    //	u32 insns;
    //	u32 insns_len;
    //};

    public static class ElfEHInfo
    {
        public const byte DW_EH_PE_absptr = 0x00;
        public const byte DW_EH_PE_omit = 0xff;

        public const byte DW_EH_PE_uleb128 = 0x01;
        public const byte DW_EH_PE_udata2 = 0x02;
        public const byte DW_EH_PE_udata4 = 0x03;
        public const byte DW_EH_PE_udata8 = 0x04;
        public const byte DW_EH_PE_sleb128 = 0x09;
        public const byte DW_EH_PE_sdata2 = 0x0A;
        public const byte DW_EH_PE_sdata4 = 0x0B;
        public const byte DW_EH_PE_sdata8 = 0x0C;
        public const byte DW_EH_PE_signed = 0x08;

        public const byte DW_EH_PE_pcrel = 0x10;
        public const byte DW_EH_PE_textrel = 0x20;
        public const byte DW_EH_PE_datarel = 0x30;
        public const byte DW_EH_PE_funcrel = 0x40;
        public const byte DW_EH_PE_aligned = 0x50;

        public const byte DW_EH_PE_indirect = 0x80;

        public static bool MeasureFrame(ReadOnlySpan<byte> image, int headerOffset, out uint ehFramePtr, out uint ehFrameLength)
        {
            var headerPtr = image.Slice(headerOffset);
            var header = new EhFrameHdr(headerPtr);
            if (header.version != 1)
            {
                ehFramePtr = 0;
                ehFrameLength = 0;
                return false;
            }

            var bufferPtr = headerOffset + EhFrameHdr.Length;
            uint dw_decode(ReadOnlySpan<byte> image, byte enc)
            {
                uint val = 0;
                var basePtr = bufferPtr;
                switch (enc & 0x70)
                {
                    case DW_EH_PE_absptr:
                        break;
                    case DW_EH_PE_pcrel:
                        val += (uint)basePtr;
                        break;
                    case DW_EH_PE_datarel:
                        val += (uint)headerOffset;
                        break;
                    default:
                        throw new Exception($"Unexpected enc base {enc}");
                }
                switch (enc & 0x0f)
                {
                    case DW_EH_PE_udata2:
                        val += BinaryPrimitives.ReadUInt16LittleEndian(image.Slice(bufferPtr));
                        bufferPtr += 2;
                        break;
                    case DW_EH_PE_udata4:
                        val += BinaryPrimitives.ReadUInt32LittleEndian(image.Slice(bufferPtr));
                        bufferPtr += 4;
                        break;
                    case DW_EH_PE_sdata4:
                        val += (uint)BinaryPrimitives.ReadInt32LittleEndian(image.Slice(bufferPtr));
                        bufferPtr += 4;
                        break;
                    default:
                        throw new Exception($"Unexpected enc type {enc}");
                }
                if ((enc & DW_EH_PE_indirect) != 0)
                {
                    val = BinaryPrimitives.ReadUInt32LittleEndian(image.Slice((int)val));
                }
                return val;
            }

            uint dw_fde_len(ReadOnlySpan<byte> image, int offset)
            {
                var len = BinaryPrimitives.ReadUInt32LittleEndian(image.Slice(bufferPtr));
                bufferPtr += 4;
                if (len == 0xffffffff)
                {
                    throw new Exception("Reading fde failed");
                }

                return len;
            }

            ehFramePtr = dw_decode(image, header.eh_frame_ptr_enc);
            var fdeCount = dw_decode(image, header.fde_count_enc);
            uint maxPtr = 0;
            for (int i = 0; i < fdeCount; i++)
            {
                var desc = dw_decode(image, header.table_enc);
                uint fdeLen = dw_fde_len(image, (int)desc);
                maxPtr = Math.Max(maxPtr, desc + fdeLen);
            }
            if (maxPtr != 0)
            {
                ehFrameLength = maxPtr;
            }
            else
            {
                ehFrameLength = 0;
            }
            return true;
        }
    }
}
