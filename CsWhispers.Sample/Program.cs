using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;

namespace CsWhispers.Sample;

internal static unsafe class Program
{

    public static void Main(string[] args)
    {
        using var self = Process.GetCurrentProcess();

        NTSTATUS status;
        HANDLE hProcess;
        OBJECT_ATTRIBUTES oa;
        CLIENT_ID cid = new()
        {
            UniqueProcess = new((IntPtr)self.Id)
        };

        status = NtOpenProcess(
            &hProcess,
            PROCESS_ALL_ACCESS,
            &oa,
            &cid);

        Console.WriteLine("Status: 0x{0:X}", status);
        ;
    }
}