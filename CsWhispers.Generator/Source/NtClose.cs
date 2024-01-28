using System.Runtime.InteropServices;

namespace CsWhispers;

public static unsafe partial class Syscalls
{
    private const string ZwCloseHash = "F11693417BD581AAA27083765DB7A812";

    public static NTSTATUS NtClose(HANDLE handle)
    {
        var stub = GetSyscallStub(ZwCloseHash);

        fixed (byte* buffer = stub)
        {
            var ptr = (IntPtr)buffer;
            var size = new IntPtr(stub.Length);
            
            Native.NtProtectVirtualMemory(
                new HANDLE((IntPtr)(-1)),
                ref ptr,
                ref size,
                0x00000020,
                out var oldProtect);

            var ntClose = Marshal.GetDelegateForFunctionPointer<ZwClose>(ptr);
            
            var status = ntClose(handle);

            Native.NtProtectVirtualMemory(
                new HANDLE((IntPtr)(-1)),
                ref ptr,
                ref size,
                oldProtect,
                out _);

            return status;
        }
    }
    
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate NTSTATUS ZwClose(HANDLE handle);
}