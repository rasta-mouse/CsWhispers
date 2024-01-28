using System.Diagnostics;

namespace CsWhispers.Sample;

internal static unsafe class Program
{
    public static void Main(string[] args)
    {
        using var self = Process.GetCurrentProcess();
        
        NTSTATUS status;
        HANDLE hProcess;
        OBJECT_ATTRIBUTES oa;

        var cid = new CLIENT_ID
        {
            UniqueProcess = new HANDLE((IntPtr)self.Id)
        };

        status = NtOpenProcess(
            &hProcess,
            PROCESS_ALL_ACCESS,
            &oa,
            &cid);

        Console.WriteLine("Status: {0}", status.SeverityCode);
        Console.WriteLine("HANDLE: 0x{0:X}", hProcess.Value.ToInt64());
    }
}