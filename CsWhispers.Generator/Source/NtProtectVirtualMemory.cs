using System.Runtime.InteropServices;

namespace CsWhispers;

public static unsafe partial class Syscalls
{
    private const string ZwProtectVirtualMemoryHash = "95429C4A177A230D88166479D035C143";

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
            var ptr = (IntPtr)buffer;
            var size = new IntPtr(stub.Length);

            Native.NtProtectVirtualMemory(
                new HANDLE((IntPtr)(-1)),
                ref ptr,
                ref size,
                0x00000020,
                out var oldProtect);

            var ntProtectVirtualMemory = Marshal.GetDelegateForFunctionPointer<ZwProtectVirtualMemory>(ptr);

            var status = ntProtectVirtualMemory(
                processHandle,
                baseAddress,
                numberOfBytesToProtect,
                newAccessProtection,
                oldAccessProtection);

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
    private delegate NTSTATUS ZwProtectVirtualMemory(
        HANDLE processHandle,
        void* baseAddress,
        uint* numberOfBytesToProtect,
        uint newAccessProtection,
        uint* oldAccessProtection);
}