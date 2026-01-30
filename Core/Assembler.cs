using System;
using System.Collections.Generic;

namespace EFE_s_NativeInjector.Core
{
    public class Assembler
    {
        private List<byte> buf = new List<byte>();

        public byte[] ToByteArray() => buf.ToArray();

        private void Add(params byte[] b) { buf.AddRange(b); }

        public void Push(IntPtr v)
        {
            Add(0x68);
            Add(BitConverter.GetBytes(v.ToInt32()));
        }

        public void MovEax(IntPtr v)
        {
            Add(0xB8);
            Add(BitConverter.GetBytes(v.ToInt32()));
        }

        public void CallEax()
        {
            Add(0xFF, 0xD0);
        }

        public void AddEsp(byte n)
        {
            Add(0x83, 0xC4, n);
        }

        public void MovEaxTo(IntPtr addr)
        {
            Add(0xA3);
            Add(BitConverter.GetBytes(addr.ToInt32()));
        }

        public void Return()
        {
            Add(0xC3);
        }

        public void SubRsp(byte n)
        {
            Add(0x48, 0x83, 0xEC, n);
        }

        public void AddRsp(byte n)
        {
            Add(0x48, 0x83, 0xC4, n);
        }

        public void MovRax(IntPtr v)
        {
            Add(0x48, 0xB8);
            Add(BitConverter.GetBytes(v.ToInt64()));
        }

        public void MovRcx(IntPtr v)
        {
            Add(0x48, 0xB9);
            Add(BitConverter.GetBytes(v.ToInt64()));
        }

        public void MovRdx(IntPtr v)
        {
            Add(0x48, 0xBA);
            Add(BitConverter.GetBytes(v.ToInt64()));
        }

        public void MovR8(IntPtr v)
        {
            Add(0x49, 0xB8);
            Add(BitConverter.GetBytes(v.ToInt64()));
        }

        public void MovR9(IntPtr v)
        {
            Add(0x49, 0xB9);
            Add(BitConverter.GetBytes(v.ToInt64()));
        }

        public void CallRax()
        {
            Add(0xFF, 0xD0);
        }

        public void MovRaxTo(IntPtr addr)
        {
            Add(0x48, 0xA3);
            Add(BitConverter.GetBytes(addr.ToInt64()));
        }
    }
}
