using System.Runtime.InteropServices;

namespace CsWhispers;

public static unsafe partial class Syscalls
{
    private const string ZwFreeVirtualMemoryHash = "A2356248E8839427AE2D390367DC1A40";

    public static NTSTATUS NtFreeVirtualMemory(
        HANDLE processHandle,
        void* baseAddress,
        uint* regionSize,
        uint freeType)
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

            var ntFreeVirtualMemory = Marshal.GetDelegateForFunctionPointer<ZwFreeVirtualMemory>(ptr);

            var status = ntFreeVirtualMemory(
                processHandle,
                baseAddress,
                regionSize,
                freeType);

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
    private delegate NTSTATUS ZwFreeVirtualMemory(
        HANDLE processHandle,
        void* baseAddress,
        uint* regionSize,
        uint freeType);
}

public static partial class Constants
{
    public const uint MEM_DECOMMIT = 0x00004000;
    public const uint MEM_RELEASE = 0x00008000;
}