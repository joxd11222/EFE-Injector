using System;
using System.Collections.Generic;

namespace EFE_s_NativeInjector.Core
{
    public class Asm
    {
        List<byte> buf = new List<byte>();

        public byte[] Get() => buf.ToArray();

        void Add(params byte[] b) => buf.AddRange(b);

        public void Push32(IntPtr v)
        {
            Add(0x68);
            Add(BitConverter.GetBytes(v.ToInt32()));
        }

        public void Mov32Eax(IntPtr v)
        {
            Add(0xB8);
            Add(BitConverter.GetBytes(v.ToInt32()));
        }

        public void CallEax() => Add(0xFF, 0xD0);

        public void AddEsp(byte n) => Add(0x83, 0xC4, n);

        public void StoreEax(IntPtr addr)
        {
            Add(0xA3);
            Add(BitConverter.GetBytes(addr.ToInt32()));
        }

        public void Ret() => Add(0xC3);

        public void SubRsp(byte n) => Add(0x48, 0x83, 0xEC, n);

        public void AddRsp(byte n) => Add(0x48, 0x83, 0xC4, n);

        public void Mov64Rax(IntPtr v)
        {
            Add(0x48, 0xB8);
            Add(BitConverter.GetBytes(v.ToInt64()));
        }

        public void Mov64Rcx(IntPtr v)
        {
            Add(0x48, 0xB9);
            Add(BitConverter.GetBytes(v.ToInt64()));
        }

        public void Mov64Rdx(IntPtr v)
        {
            Add(0x48, 0xBA);
            Add(BitConverter.GetBytes(v.ToInt64()));
        }

        public void Mov64R8(IntPtr v)
        {
            Add(0x49, 0xB8);
            Add(BitConverter.GetBytes(v.ToInt64()));
        }

        public void Mov64R9(IntPtr v)
        {
            Add(0x49, 0xB9);
            Add(BitConverter.GetBytes(v.ToInt64()));
        }

        public void CallRax() => Add(0xFF, 0xD0);

        public void StoreRax(IntPtr addr)
        {
            Add(0x48, 0xA3);
            Add(BitConverter.GetBytes(addr.ToInt64()));
        }
    }
}
