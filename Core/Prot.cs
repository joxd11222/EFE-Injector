using System;

namespace EFE_s_NativeInjector.Core
{
    public static class Prot
    {
        public static void ErasePE(IntPtr hProc, IntPtr baseAddr)
        {
            uint old;
            Native.VirtualProtectEx(hProc, baseAddr, 4096, Native.PAGE_RW, out old);
            byte[] zeros = new byte[4096];
            Native.WriteProcessMemory(hProc, baseAddr, zeros, 4096, out _);
            Native.VirtualProtectEx(hProc, baseAddr, 4096, old, out _);
        }

        public static void Wipe(IntPtr hProc, IntPtr addr, uint size)
        {
            uint old;
            Native.VirtualProtectEx(hProc, addr, size, Native.PAGE_RW, out old);
            byte[] zeros = new byte[size];
            Native.WriteProcessMemory(hProc, addr, zeros, size, out _);
            Native.VirtualFreeEx(hProc, addr, 0, Native.MEM_RELEASE);
        }
    }
}
