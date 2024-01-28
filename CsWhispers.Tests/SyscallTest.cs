using System.Diagnostics;

namespace CsWhispers.Tests;

public sealed class SyscallTest
{
    [Fact]
    public static unsafe void OpenProcess()
    {
        using var self = Process.GetCurrentProcess();

        NTSTATUS status;
        HANDLE hProcess;
        OBJECT_ATTRIBUTES oa;
        
        CLIENT_ID cid = new()
        {
            UniqueProcess = (HANDLE)self.Id
        };

        status = NtOpenProcess(
            &hProcess,
            PROCESS_ALL_ACCESS,
            &oa,
            &cid);
        
        Assert.Equal(NTSTATUS.Severity.Success, status.SeverityCode);
        Assert.NotEqual(HANDLE.Null, hProcess);
    }
}