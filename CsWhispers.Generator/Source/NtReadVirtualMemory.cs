using System.Runtime.InteropServices;

namespace CsWhispers;

public static unsafe partial class Syscalls
{
    private const string ZwReadVirtualMemoryHash = "A2EAF21913E6BA93656FC0BEC4F1B7B1";

    public static NTSTATUS NtReadVirtualMemory(
        HANDLE processHandle,
        void* baseAddress,
        void* buffer,
        uint numberOfBytesToRead,
        [Optional] uint* numberOfBytesRead)
    {
        var stub = GetSyscallStub(ZwReadVirtualMemoryHash);

        fixed (byte* temp = stub)
        {
            var ptr = (IntPtr)temp;
            var size = new IntPtr(stub.Length);

            Native.NtProtectVirtualMemory(
                new HANDLE((IntPtr)(-1)),
                ref ptr,
                ref size,
                0x00000020,
                out var oldProtect);

            var ntReadVirtualMemory = Marshal.GetDelegateForFunctionPointer<ZwReadVirtualMemory>(ptr);

            var status = ntReadVirtualMemory(
                processHandle,
                baseAddress,
                buffer,
                numberOfBytesToRead,
                numberOfBytesRead);

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
    private delegate NTSTATUS ZwReadVirtualMemory(
        HANDLE processHandle,
        void* baseAddress,
        void* buffer,
        uint numberOfBytesToRead,
        [Optional] uint* numberOfBytesRead);
}