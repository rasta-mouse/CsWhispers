using System.Runtime.InteropServices;

namespace CsWhispers;

public static unsafe partial class Syscalls
{
    private const string ZwWriteVirtualMemoryHash = "8ECD3BD989CAB9EFE34A0625285BAA0F";

    public static NTSTATUS NtWriteVirtualMemory(
        HANDLE processHandle,
        void* baseAddress,
        void* buffer,
        uint numberOfBytesToWrite,
        [Optional] uint* numberOfBytesWritten)
    {
        var stub = GetSyscallStub(ZwWriteVirtualMemoryHash);

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

            var ntWriteVirtualMemory = Marshal.GetDelegateForFunctionPointer<ZwWriteVirtualMemory>(ptr);

            var status = ntWriteVirtualMemory(
                processHandle,
                baseAddress,
                buffer,
                numberOfBytesToWrite,
                numberOfBytesWritten);

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
    private delegate NTSTATUS ZwWriteVirtualMemory(
        HANDLE processHandle,
        void* baseAddress,
        void* buffer,
        uint numberOfBytesToWrite,
        [Optional] uint* numberOfBytesWritten);
}