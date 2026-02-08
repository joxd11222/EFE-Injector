using System;
using System.Runtime.InteropServices;

namespace EFE_s_NativeInjector.Core
{
    public static class Native
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr VirtualAllocEx(IntPtr hProc, IntPtr addr, uint size, uint type, uint protect);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(IntPtr hProc, IntPtr addr, byte[] buf, uint size, out IntPtr written);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(IntPtr hProc, IntPtr addr, byte[] buf, uint size, out IntPtr read);
        [DllImport("kernel32.dll")]
        public static extern IntPtr CreateRemoteThread(IntPtr hProc, IntPtr attr, uint stack, IntPtr start, IntPtr param, uint flags, out IntPtr tid);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool VirtualProtectEx(IntPtr hProc, IntPtr addr, uint size, uint newProt, out uint oldProt);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern int WaitForSingleObject(IntPtr handle, int ms);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr handle);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool VirtualFreeEx(IntPtr hProc, IntPtr addr, uint size, uint type);
        [DllImport("kernel32.dll")]
        public static extern bool IsWow64Process(IntPtr hProc, out bool wow64);
        public const uint PROCESS_ALL = 0x1F0FFF;
        public const uint MEM_COMMIT = 0x1000;
        public const uint MEM_RESERVE = 0x2000;
        public const uint MEM_RELEASE = 0x8000;
        public const uint PAGE_RW = 0x04;
        public const uint PAGE_RWX = 0x40;
        public const uint PAGE_READONLY = 0x02;
        public const uint PAGE_NOACCESS = 0x01;
    }
}