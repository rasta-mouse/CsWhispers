using System.Runtime.InteropServices;

namespace CsWhispers;

public static unsafe partial class Syscalls
{
    private const string ZwUnmapViewOfSectionHash = "57447AEA45A1F4B2C045B0E316FE8F12";

    public static NTSTATUS NtUnmapViewOfSection(
        HANDLE processHandle,
        [Optional] void* baseAddress)
    {
        var stub = GetSyscallStub(ZwUnmapViewOfSectionHash);

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

            var ntUnmapViewOfSection = Marshal.GetDelegateForFunctionPointer<ZwUnmapViewOfSection>(ptr);

            var status = ntUnmapViewOfSection(
                processHandle,
                baseAddress);

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
    private delegate NTSTATUS ZwUnmapViewOfSection(
        HANDLE processHandle,
        [Optional] void* baseAddress);
}