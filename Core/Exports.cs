using System;
using System.Collections.Generic;

namespace EFE_s_NativeInjector.Core
{
    public class Exports
    {
        Memory mem;
        IntPtr modBase;
        Dictionary<string, IntPtr> cache = new Dictionary<string, IntPtr>();

        public Exports(Memory m, IntPtr baseAddr)
        {
            mem = m;
            modBase = baseAddr;
        }

        public IntPtr Get(string name)
        {
            if (cache.TryGetValue(name, out IntPtr cached))
                return cached;

            int peOff = mem.ReadInt(modBase + 0x3C);
            IntPtr pe = modBase + peOff;

            int expRva = mem.X64 ? mem.ReadInt(pe + 0x88) : mem.ReadInt(pe + 0x78);
            if (expRva == 0) return IntPtr.Zero;

            IntPtr expDir = modBase + expRva;

            int numNames = mem.ReadInt(expDir + 0x18);
            int namesRva = mem.ReadInt(expDir + 0x20);
            int funcsRva = mem.ReadInt(expDir + 0x1C);
            int ordsRva = mem.ReadInt(expDir + 0x24);

            IntPtr names = modBase + namesRva;
            IntPtr funcs = modBase + funcsRva;
            IntPtr ords = modBase + ordsRva;

            for (int i = 0; i < numNames; i++)
            {
                int nameRva = mem.ReadInt(names + i * 4);
                string fn = mem.ReadStr(modBase + nameRva, 256);

                if (fn == name)
                {
                    ushort ord = mem.ReadUShort(ords + i * 2);
                    int funcRva = mem.ReadInt(funcs + ord * 4);
                    IntPtr addr = modBase + funcRva;
                    cache[name] = addr;
                    return addr;
                }
            }

            return IntPtr.Zero;
        }
    }
}
