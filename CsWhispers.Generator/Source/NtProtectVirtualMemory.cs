using System.Runtime.InteropServices;

namespace CsWhispers;

public static unsafe partial class Syscalls
{
    private const string ZwProtectVirtualMemoryHash = "95429C4A177A230D88166479D035C143";

    private static int NtProtectVirtualMemoryJit() { return 5; }

    public static NTSTATUS NtProtectVirtualMemory(
        HANDLE processHandle,
        void* baseAddress,
        uint* numberOfBytesToProtect,
        uint newAccessProtection,
        uint* oldAccessProtection)
    {
        var stub = GetSyscallStub(ZwProtectVirtualMemoryHash);

        fixed (byte* buffer = stub)
        {
            IntPtr ptr = PrepareJit(nameof(NtProtectVirtualMemoryJit), buffer, stub.Length);

            var ntProtectVirtualMemory = Marshal.GetDelegateForFunctionPointer<ZwProtectVirtualMemory>(ptr);

            var status = ntProtectVirtualMemory(
                processHandle,
                baseAddress,
                numberOfBytesToProtect,
                newAccessProtection,
                oldAccessProtection);

            return status;
        }
    }

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate NTSTATUS ZwProtectVirtualMemory(
        HANDLE processHandle,
        void* baseAddress,
        uint* numberOfBytesToProtect,
        uint newAccessProtection,
        uint* oldAccessProtection);
}