using System;
using System.Text;

namespace EFE_s_NativeInjector.Core
{
    public class Memory : IDisposable
    {
        IntPtr hProc;
        public bool X64 { get; private set; }

        public Memory(IntPtr handle, bool is64)
        {
            hProc = handle;
            X64 = is64;
        }

        public void Dispose() { }

        public IntPtr Alloc(int size)
        {
            return Native.VirtualAllocEx(hProc, IntPtr.Zero, (uint)size, Native.MEM_COMMIT | Native.MEM_RESERVE, Native.PAGE_RWX);
        }

        public IntPtr AllocWrite(byte[] data)
        {
            IntPtr addr = Alloc(data.Length);
            if (addr != IntPtr.Zero) Write(addr, data);
            return addr;
        }

        public IntPtr AllocWrite(int val) => AllocWrite(BitConverter.GetBytes(val));

        public IntPtr AllocWrite(long val) => AllocWrite(BitConverter.GetBytes(val));

        public IntPtr AllocWrite(string s) => AllocWrite(Encoding.UTF8.GetBytes(s + "\0"));

        public void Free(IntPtr addr)
        {
            if (addr != IntPtr.Zero) Native.VirtualFreeEx(hProc, addr, 0, Native.MEM_RELEASE);
        }

        public bool Write(IntPtr addr, byte[] data)
        {
            return Native.WriteProcessMemory(hProc, addr, data, (uint)data.Length, out _);
        }

        public byte[] Read(IntPtr addr, int size)
        {
            byte[] buf = new byte[size];
            Native.ReadProcessMemory(hProc, addr, buf, (uint)size, out _);
            return buf;
        }

        public int ReadInt(IntPtr addr) => BitConverter.ToInt32(Read(addr, 4), 0);

        public long ReadLong(IntPtr addr) => BitConverter.ToInt64(Read(addr, 8), 0);

        public ushort ReadUShort(IntPtr addr) => BitConverter.ToUInt16(Read(addr, 2), 0);

        public string ReadStr(IntPtr addr, int max)
        {
            byte[] buf = Read(addr, max);
            int end = Array.IndexOf(buf, (byte)0);
            if (end < 0) end = max;
            return Encoding.ASCII.GetString(buf, 0, end);
        }
    }
}
