using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;

namespace EFE_s_NativeInjector.Core
{
    public static class AntiProt
    {
        [DllImport("kernel32.dll")]
        static extern IntPtr GetModuleHandle(string name);

        [DllImport("kernel32.dll")]
        static extern bool VirtualProtect(IntPtr addr, uint size, uint prot, out uint old);

        [DllImport("kernel32.dll")]
        static extern IntPtr GetCurrentProcess();

        [DllImport("ntdll.dll")]
        static extern int NtQueryInformationProcess(IntPtr hProc, int cls, ref IntPtr info, int size, ref int ret);

        public static bool CheckDebugger()
        {
            try
            {
                IntPtr dbgPort = IntPtr.Zero;
                int retLen = 0;
                NtQueryInformationProcess(GetCurrentProcess(), 7, ref dbgPort, IntPtr.Size, ref retLen);
                return dbgPort != IntPtr.Zero;
            }
            catch { return false; }
        }

        public static void UnhookNtdll()
        {
            try
            {
                string path = Path.Combine(Environment.SystemDirectory, "ntdll.dll");
                if (!File.Exists(path)) return;

                byte[] clean = File.ReadAllBytes(path);
                IntPtr mod = GetModuleHandle("ntdll.dll");
                if (mod == IntPtr.Zero) return;

                int peOff = Marshal.ReadInt32(mod + 0x3C);
                IntPtr peHdr = mod + peOff;
                short numSec = Marshal.ReadInt16(peHdr + 0x6);
                int optSize = Marshal.ReadInt16(peHdr + 0x14);
                IntPtr secHdr = peHdr + 0x18 + optSize;

                for (int i = 0; i < numSec; i++)
                {
                    IntPtr sec = secHdr + (i * 40);
                    byte[] secName = new byte[8];
                    Marshal.Copy(sec, secName, 0, 8);
                    string name = System.Text.Encoding.ASCII.GetString(secName).TrimEnd('\0');

                    if (name == ".text")
                    {
                        uint virtSize = (uint)Marshal.ReadInt32(sec + 8);
                        uint virtAddr = (uint)Marshal.ReadInt32(sec + 12);
                        uint rawAddr = (uint)Marshal.ReadInt32(sec + 20);

                        IntPtr txtAddr = mod + (int)virtAddr;
                        uint oldProt;
                        VirtualProtect(txtAddr, virtSize, 0x40, out oldProt);
                        Marshal.Copy(clean, (int)rawAddr, txtAddr, (int)virtSize);
                        VirtualProtect(txtAddr, virtSize, oldProt, out _);
                        break;
                    }
                }
            }
            catch { }
        }
    }
}
