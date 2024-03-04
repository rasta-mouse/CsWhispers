using System.Runtime.InteropServices;

namespace CsWhispers;

public static unsafe partial class Syscalls
{
    private const string ZwReadVirtualMemoryHash = "A2EAF21913E6BA93656FC0BEC4F1B7B1";

    private static int NtReadVirtualMemoryJit() { return 5; }

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
            IntPtr ptr = PrepareJit(nameof(NtReadVirtualMemoryJit), temp, stub.Length);

            var ntReadVirtualMemory = Marshal.GetDelegateForFunctionPointer<ZwReadVirtualMemory>(ptr);

            var status = ntReadVirtualMemory(
                processHandle,
                baseAddress,
                buffer,
                numberOfBytesToRead,
                numberOfBytesRead);

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