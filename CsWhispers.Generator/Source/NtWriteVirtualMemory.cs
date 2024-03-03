using System.Runtime.InteropServices;

namespace CsWhispers;

public static unsafe partial class Syscalls
{
    private const string ZwWriteVirtualMemoryHash = "8ECD3BD989CAB9EFE34A0625285BAA0F";

    private static int NtWriteVirtualMemoryJit() { return 5; }

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
            IntPtr ptr = PrepareJit(nameof(NtWriteVirtualMemoryJit), temp, stub.Length);

            var ntWriteVirtualMemory = Marshal.GetDelegateForFunctionPointer<ZwWriteVirtualMemory>(ptr);

            var status = ntWriteVirtualMemory(
                processHandle,
                baseAddress,
                buffer,
                numberOfBytesToWrite,
                numberOfBytesWritten);

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