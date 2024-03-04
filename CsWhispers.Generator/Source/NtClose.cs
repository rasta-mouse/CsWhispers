using System.Runtime.InteropServices;

namespace CsWhispers;

public static unsafe partial class Syscalls
{
    private const string ZwCloseHash = "D5E973CE71E99CE43DB3C3FFFFEB4623";

    private static int NtCloseJit() { return 5; }

    public static NTSTATUS NtClose(HANDLE handle)
    {
        var stub = GetSyscallStub(ZwCloseHash);

        fixed (byte* buffer = stub)
        {
            IntPtr ptr = PrepareJit(nameof(NtCloseJit), buffer, stub.Length);

            var ntClose = Marshal.GetDelegateForFunctionPointer<ZwClose>(ptr);
            
            var status = ntClose(handle);

            return status;
        }
    }
    
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate NTSTATUS ZwClose(HANDLE handle);
}