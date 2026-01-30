using System;
using System.Diagnostics;
using System.Threading;
using EFE_s_NativeInjector.Core;

namespace EFE_s_NativeInjector
{
    class Program
    {
        static void Main(string[] args)
        {
            if (Debugger.IsAttached || AntiProt.CheckDebugger())
            {
                Environment.Exit(0);
                return;
            }

            AntiProt.UnhookNtdll();

            Console.Title = "EFE's Injector";
            Console.WriteLine("EFE's NativeInjector");
            Console.WriteLine("====================");

            string dllPath, ns, cls, method;

            if (args.Length >= 4)
            {
                dllPath = args[0];
                ns = args[1];
                cls = args[2];
                method = args[3];
            }
            else
            {
                Console.Write("DLL Path: ");
                dllPath = Console.ReadLine().Trim().Trim('"');

                if (string.IsNullOrEmpty(dllPath) || !System.IO.File.Exists(dllPath))
                {
                    Console.WriteLine("invalid path");
                    Console.ReadKey();
                    return;
                }

                Console.Write("Namespace: ");
                ns = Console.ReadLine().Trim();

                Console.Write("Class: ");
                cls = Console.ReadLine().Trim();

                Console.Write("Method: ");
                method = Console.ReadLine().Trim();
            }

            Console.WriteLine("\nwaiting for gorilla tag...");

            while (true)
            {
                var procs = Process.GetProcessesByName("Gorilla Tag");
                if (procs.Length > 0) break;
                Thread.Sleep(500);
            }

            Console.WriteLine("found, waiting for mono...");
            Thread.Sleep(1000);

            try
            {
                using (var inj = new Injector("Gorilla Tag"))
                {
                    Console.WriteLine("injecting...");

                    bool res = inj.InjectFile(dllPath, ns, cls, method);

                    if (res)
                        Console.WriteLine("done!");
                    else
                        Console.WriteLine("failed: " + inj.LastError);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("error: " + ex.Message);
            }

            Console.ReadKey();
        }
    }
}
