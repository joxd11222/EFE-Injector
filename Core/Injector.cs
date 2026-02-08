using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace EFE_s_NativeInjector.Core
{
    public class Injector : IDisposable
    {
        IntPtr hProc;
        IntPtr monoMod;
        Memory mem;
        Exports exp;
        IntPtr rootDomain;
        bool attached;
        string err;
        List<IntPtr> allocations = new List<IntPtr>();

        Dictionary<string, IntPtr> fn = new Dictionary<string, IntPtr>();

        public bool X64 { get; private set; }
        public string LastError => err;

        public Injector(string procName)
        {
            Process proc = Process.GetProcessesByName(procName).FirstOrDefault();
            if (proc == null) throw new Exception("process not found: " + procName);

            hProc = Native.OpenProcess(Native.PROCESS_ALL, false, proc.Id);
            if (hProc == IntPtr.Zero) throw new Exception("openprocess failed");

            bool wow64;
            Native.IsWow64Process(hProc, out wow64);
            X64 = !wow64 && Environment.Is64BitOperatingSystem;

            monoMod = FindMono(proc);
            if (monoMod == IntPtr.Zero) throw new Exception("mono not found");

            mem = new Memory(hProc, X64);
            exp = new Exports(mem, monoMod);

            LoadFuncs();
        }

        public void Dispose()
        {
            CleanAllocations();
            mem?.Dispose();
            if (hProc != IntPtr.Zero) Native.CloseHandle(hProc);
        }

        void CleanAllocations()
        {
            foreach (var addr in allocations)
            {
                if (addr != IntPtr.Zero)
                {
                    byte[] zeros = new byte[4096];
                    uint oldProt;
                    Native.VirtualProtectEx(hProc, addr, 4096, Native.PAGE_RW, out oldProt);
                    Native.WriteProcessMemory(hProc, addr, zeros, 4096, out _);
                    Native.VirtualFreeEx(hProc, addr, 0, Native.MEM_RELEASE);
                }
            }
            allocations.Clear();
        }

        IntPtr AllocTracked(byte[] data)
        {
            IntPtr addr = mem.AllocWrite(data);
            if (addr != IntPtr.Zero) allocations.Add(addr);
            return addr;
        }

        IntPtr FindMono(Process p)
        {
            foreach (ProcessModule m in p.Modules)
            {
                string n = m.ModuleName.ToLower();
                if (n.Contains("mono") && n.EndsWith(".dll"))
                    return m.BaseAddress;
            }
            return IntPtr.Zero;
        }

        void LoadFuncs()
        {
            string[] funcs = {
                "mono_get_root_domain",
                "mono_thread_attach",
                "mono_image_open_from_data",
                "mono_assembly_load_from_full",
                "mono_assembly_get_image",
                "mono_class_from_name",
                "mono_class_get_method_from_name",
                "mono_runtime_invoke"
            };

            foreach (string name in funcs)
            {
                IntPtr addr = exp.Get(name);
                if (addr == IntPtr.Zero) throw new Exception("export missing: " + name);
                fn[name] = addr;
            }
        }

        byte[] encrypt(byte[] data)
        {
            byte[] key = new byte[32];
            byte[] iv = new byte[16];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(key);
                rng.GetBytes(iv);
            }

            byte[] enc;
            using (var aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                using (var e = aes.CreateEncryptor())
                    enc = e.TransformFinalBlock(data, 0, data.Length);
            }

            byte[] res = new byte[48 + enc.Length];
            Buffer.BlockCopy(key, 0, res, 0, 32);
            Buffer.BlockCopy(iv, 0, res, 32, 16);
            Buffer.BlockCopy(enc, 0, res, 48, enc.Length);
            return res;
        }

        byte[] decrypt(byte[] data)
        {
            byte[] key = new byte[32];
            byte[] iv = new byte[16];
            byte[] enc = new byte[data.Length - 48];

            Buffer.BlockCopy(data, 0, key, 0, 32);
            Buffer.BlockCopy(data, 32, iv, 0, 16);
            Buffer.BlockCopy(data, 48, enc, 0, enc.Length);

            using (var aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                using (var d = aes.CreateDecryptor())
                    return d.TransformFinalBlock(enc, 0, enc.Length);
            }
        }

        void Wipe(byte[] arr)
        {
            for (int i = 0; i < arr.Length; i++) arr[i] = 0;
        }

        public IntPtr Inject(byte[] rawDll, string ns, string className, string methodName)
        {
            err = "";

            rootDomain = Call(fn["mono_get_root_domain"]);
            if (rootDomain == IntPtr.Zero) { err = "mono_get_root_domain failed"; return IntPtr.Zero; }

            if (!attached)
            {
                Call(fn["mono_thread_attach"], rootDomain);
                attached = true;
            }

            IntPtr status = mem.AllocWrite(0);
            allocations.Add(status);

            IntPtr dllPtr = AllocTracked(rawDll);
            int dllLen = rawDll.Length;

            IntPtr rawImg = Call(fn["mono_image_open_from_data"],
                dllPtr,
                (IntPtr)dllLen,
                (IntPtr)1,
                status);

            if (rawImg == IntPtr.Zero) { err = "mono_image_open_from_data failed"; return IntPtr.Zero; }

            byte[] emptyName = new byte[] { 0 };
            IntPtr namePtr = AllocTracked(emptyName);

            IntPtr asm = Call(fn["mono_assembly_load_from_full"],
                rawImg,
                namePtr,
                status,
                IntPtr.Zero);

            if (asm == IntPtr.Zero) { err = "mono_assembly_load_from_full failed"; return IntPtr.Zero; }

            IntPtr img = Call(fn["mono_assembly_get_image"], asm);
            if (img == IntPtr.Zero) { err = "mono_assembly_get_image failed"; return IntPtr.Zero; }

            IntPtr nsPtr = AllocTracked(System.Text.Encoding.UTF8.GetBytes((ns ?? "") + "\0"));
            IntPtr clsPtr = AllocTracked(System.Text.Encoding.UTF8.GetBytes(className + "\0"));

            IntPtr klass = Call(fn["mono_class_from_name"], img, nsPtr, clsPtr);
            if (klass == IntPtr.Zero) { err = "class not found: " + (ns ?? "") + "." + className; return IntPtr.Zero; }

            IntPtr methPtr = AllocTracked(System.Text.Encoding.UTF8.GetBytes(methodName + "\0"));

            IntPtr method = Call(fn["mono_class_get_method_from_name"], klass, methPtr, IntPtr.Zero);
            if (method == IntPtr.Zero) { err = "method not found: " + methodName; return IntPtr.Zero; }

            IntPtr exc = X64 ? mem.AllocWrite((long)0) : mem.AllocWrite(0);
            allocations.Add(exc);

            Call(fn["mono_runtime_invoke"], method, IntPtr.Zero, IntPtr.Zero, exc);

            IntPtr excVal = X64 ? (IntPtr)mem.ReadLong(exc) : (IntPtr)mem.ReadInt(exc);
            if (excVal != IntPtr.Zero)
            {
                err = "method threw exception";
                return IntPtr.Zero;
            }

            System.Threading.Thread.Sleep(200);

            hideeeee(asm, rawImg, dllPtr, dllLen);

            return asm;
        }

        void hideeeee(IntPtr asm, IntPtr imgAddr, IntPtr dllPtr, int dllLen)
        {
            try
            {
                unlinkassembly(asm);
                corruptmetadata(imgAddr);
                wiperawdata(imgAddr);
                wipealloc(dllPtr, dllLen);
            }
            catch { }
        }

        void unlinkassembly(IntPtr asm)
        {
            try
            {
                int ptrSize = X64 ? 8 : 4;

                byte[] asmNameBytes = mem.Read(asm + (ptrSize * 2), ptrSize);
                IntPtr asmNamePtr = X64 ?
                    (IntPtr)BitConverter.ToInt64(asmNameBytes, 0) :
                    (IntPtr)BitConverter.ToInt32(asmNameBytes, 0);

                if (asmNamePtr != IntPtr.Zero)
                {
                    byte[] fakeName = System.Text.Encoding.UTF8.GetBytes("\0");
                    uint oldProt;
                    Native.VirtualProtectEx(hProc, asmNamePtr, (uint)fakeName.Length, Native.PAGE_RW, out oldProt);
                    Native.WriteProcessMemory(hProc, asmNamePtr, fakeName, (uint)fakeName.Length, out _);
                }

                IntPtr nullPtr = IntPtr.Zero;
                byte[] nullBytes = X64 ? BitConverter.GetBytes((long)0) : BitConverter.GetBytes(0);

                uint oldProt2;
                Native.VirtualProtectEx(hProc, asm, (uint)(ptrSize * 10), Native.PAGE_RW, out oldProt2);
                Native.WriteProcessMemory(hProc, asm + ptrSize, nullBytes, (uint)nullBytes.Length, out _);
                Native.WriteProcessMemory(hProc, asm + (ptrSize * 2), nullBytes, (uint)nullBytes.Length, out _);
            }
            catch { }
        }

        void corruptmetadata(IntPtr imgAddr)
        {
            try
            {
                int ptrSize = X64 ? 8 : 4;

                byte[] nameBytes = mem.Read(imgAddr, ptrSize);
                IntPtr namePtr = X64 ?
                    (IntPtr)BitConverter.ToInt64(nameBytes, 0) :
                    (IntPtr)BitConverter.ToInt32(nameBytes, 0);

                if (namePtr != IntPtr.Zero)
                {
                    byte[] zeros = new byte[256];
                    new Random().NextBytes(zeros);
                    uint oldProt;
                    Native.VirtualProtectEx(hProc, namePtr, 256, Native.PAGE_RW, out oldProt);
                    Native.WriteProcessMemory(hProc, namePtr, zeros, 256, out _);
                }

                byte[] corrupt = new byte[ptrSize * 30];
                new Random().NextBytes(corrupt);

                uint oldProt2;
                Native.VirtualProtectEx(hProc, imgAddr, (uint)corrupt.Length, Native.PAGE_RW, out oldProt2);
                Native.WriteProcessMemory(hProc, imgAddr, corrupt, (uint)corrupt.Length, out _);
            }
            catch { }
        }

        void wiperawdata(IntPtr imgAddr)
        {
            try
            {
                int ptrSize = X64 ? 8 : 4;

                byte[] rawDataPtrBytes = mem.Read(imgAddr + (6 * ptrSize), ptrSize);
                IntPtr rawDataPtr = X64 ?
                    (IntPtr)BitConverter.ToInt64(rawDataPtrBytes, 0) :
                    (IntPtr)BitConverter.ToInt32(rawDataPtrBytes, 0);

                byte[] rawDataLenBytes = mem.Read(imgAddr + (7 * ptrSize), 4);
                int rawDataLen = BitConverter.ToInt32(rawDataLenBytes, 0);

                if (rawDataPtr != IntPtr.Zero && rawDataLen > 0 && rawDataLen < 100000000)
                {
                    byte[] garbage = new byte[rawDataLen];
                    new Random().NextBytes(garbage);

                    uint oldProt;
                    Native.VirtualProtectEx(hProc, rawDataPtr, (uint)rawDataLen, Native.PAGE_RW, out oldProt);
                    Native.WriteProcessMemory(hProc, rawDataPtr, garbage, (uint)rawDataLen, out _);
                    Native.VirtualProtectEx(hProc, rawDataPtr, (uint)rawDataLen, Native.PAGE_NOACCESS, out _);
                }
            }
            catch { }
        }

        void wipealloc(IntPtr addr, int size)
        {
            try
            {
                uint paddedSize = (uint)(((size / 4096) + 1) * 4096);
                byte[] zeros = new byte[paddedSize];
                new Random().NextBytes(zeros);

                uint oldProt;
                Native.VirtualProtectEx(hProc, addr, paddedSize, Native.PAGE_RW, out oldProt);
                Native.WriteProcessMemory(hProc, addr, zeros, paddedSize, out _);
                Native.VirtualProtectEx(hProc, addr, paddedSize, Native.PAGE_NOACCESS, out _);
            }
            catch { }
        }

        public bool InjectFile(string path, string ns, string cls, string meth)
        {
            if (!File.Exists(path))
            {
                err = "file not found: " + path;
                return false;
            }

            byte[] raw = File.ReadAllBytes(path);
            IntPtr res = Inject(raw, ns, cls, meth);
            return res != IntPtr.Zero;
        }

        IntPtr Call(IntPtr func, params IntPtr[] args)
        {
            if (func == IntPtr.Zero) return IntPtr.Zero;

            IntPtr ret = X64 ? mem.AllocWrite((long)0) : mem.AllocWrite(0);

            byte[] code = X64 ? Build64(func, ret, args) : Build86(func, ret, args);
            IntPtr codePtr = mem.AllocWrite(code);
            allocations.Add(codePtr);

            IntPtr thread = Native.CreateRemoteThread(hProc, IntPtr.Zero, 0, codePtr, IntPtr.Zero, 0, out _);
            if (thread == IntPtr.Zero) return IntPtr.Zero;

            Native.WaitForSingleObject(thread, -1);
            Native.CloseHandle(thread);

            return X64 ? (IntPtr)mem.ReadLong(ret) : (IntPtr)mem.ReadInt(ret);
        }

        byte[] Build86(IntPtr func, IntPtr ret, IntPtr[] args)
        {
            Asm a = new Asm();

            if (attached)
            {
                a.Push32(rootDomain);
                a.Mov32Eax(fn["mono_thread_attach"]);
                a.CallEax();
                a.AddEsp(4);
            }

            for (int i = args.Length - 1; i >= 0; i--)
                a.Push32(args[i]);

            a.Mov32Eax(func);
            a.CallEax();
            a.AddEsp((byte)(args.Length * 4));
            a.StoreEax(ret);
            a.Ret();

            return a.Get();
        }

        byte[] Build64(IntPtr func, IntPtr ret, IntPtr[] args)
        {
            Asm a = new Asm();

            a.SubRsp(40);

            if (attached)
            {
                a.Mov64Rax(fn["mono_thread_attach"]);
                a.Mov64Rcx(rootDomain);
                a.CallRax();
            }

            a.Mov64Rax(func);

            for (int i = 0; i < args.Length; i++)
            {
                switch (i)
                {
                    case 0: a.Mov64Rcx(args[i]); break;
                    case 1: a.Mov64Rdx(args[i]); break;
                    case 2: a.Mov64R8(args[i]); break;
                    case 3: a.Mov64R9(args[i]); break;
                }
            }

            a.CallRax();
            a.AddRsp(40);
            a.StoreRax(ret);
            a.Ret();

            return a.Get();
        }
    }
}
