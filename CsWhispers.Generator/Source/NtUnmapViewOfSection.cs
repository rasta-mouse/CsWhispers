using System.Runtime.InteropServices;

namespace CsWhispers;

public static unsafe partial class Syscalls
{
    private const string ZwUnmapViewOfSectionHash = "57447AEA45A1F4B2C045B0E316FE8F12";

    private static int NtUnmapViewOfSectionJit() { return 5; }

    public static NTSTATUS NtUnmapViewOfSection(
        HANDLE processHandle,
        [Optional] void* baseAddress)
    {
        var stub = GetSyscallStub(ZwUnmapViewOfSectionHash);

        fixed (byte* buffer = stub)
        {
            IntPtr ptr = PrepareJit(nameof(NtUnmapViewOfSectionJit), buffer, stub.Length);

            var ntUnmapViewOfSection = Marshal.GetDelegateForFunctionPointer<ZwUnmapViewOfSection>(ptr);

            var status = ntUnmapViewOfSection(
                processHandle,
                baseAddress);

            return status;
        }
    }

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate NTSTATUS ZwUnmapViewOfSection(
        HANDLE processHandle,
        [Optional] void* baseAddress);
}