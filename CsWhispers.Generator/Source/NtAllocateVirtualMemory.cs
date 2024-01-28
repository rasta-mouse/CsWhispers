using System.Runtime.InteropServices;

namespace CsWhispers;

public static unsafe partial class Syscalls
{
    private const string ZwAllocateVirtualMemoryHash = "D80FB8F3EA00B69B2CAAB144EB70BE34";

    public static NTSTATUS NtAllocateVirtualMemory(
        HANDLE processHandle,
        void* baseAddress,
        uint zeroBits,
        uint* regionSize,
        uint allocationType,
        uint protect)
    {
        var stub = GetSyscallStub(ZwAllocateVirtualMemoryHash);

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

            var ntAllocateVirtualMemory = Marshal.GetDelegateForFunctionPointer<ZwAllocateVirtualMemory>(ptr);

            var status = ntAllocateVirtualMemory(
                processHandle,
                baseAddress,
                zeroBits,
                regionSize,
                allocationType,
                protect);

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
    private delegate NTSTATUS ZwAllocateVirtualMemory(
        HANDLE processHandle,
        void* baseAddress,
        uint zeroBits,
        uint* regionSize,
        uint allocationType,
        uint protect);
}

public static partial class Constants
{
    public const uint MEM_COMMIT = 0x00001000;
    public const uint MEM_RESERVE = 0x00002000;
    public const uint MEM_RESET = 0x00080000;
    public const uint MEM_RESET_UNDO = 0x01000000;
    public const uint MEM_REPLACE_PLACEHOLDER = 0x00004000;
    public const uint MEM_LARGE_PAGES = 0x20000000;
    public const uint MEM_RESERVE_PLACEHOLDER = 0x00040000;
    public const uint MEM_FREE = 0x00010000;

    public const uint PAGE_NOACCESS = 0x00000001;
    public const uint PAGE_READONLY = 0x00000002;
    public const uint PAGE_READWRITE = 0x00000004;
    public const uint PAGE_WRITECOPY = 0x00000008;
    public const uint PAGE_EXECUTE = 0x00000010;
    public const uint PAGE_EXECUTE_READ = 0x00000020;
    public const uint PAGE_EXECUTE_READWRITE = 0x00000040;
    public const uint PAGE_EXECUTE_WRITECOPY = 0x00000080;
    public const uint PAGE_GUARD = 0x00000100;
    public const uint PAGE_NOCACHE = 0x00000200;
    public const uint PAGE_WRITECOMBINE = 0x00000400;
    public const uint PAGE_GRAPHICS_NOACCESS = 0x00000800;
    public const uint PAGE_GRAPHICS_READONLY = 0x00001000;
    public const uint PAGE_GRAPHICS_READWRITE = 0x00002000;
    public const uint PAGE_GRAPHICS_EXECUTE = 0x00004000;
    public const uint PAGE_GRAPHICS_EXECUTE_READ = 0x00008000;
    public const uint PAGE_GRAPHICS_EXECUTE_READWRITE = 0x00010000;
    public const uint PAGE_GRAPHICS_COHERENT = 0x00020000;
    public const uint PAGE_GRAPHICS_NOCACHE = 0x00040000;
    public const uint PAGE_ENCLAVE_THREAD_CONTROL = 0x80000000;
    public const uint PAGE_REVERT_TO_FILE_MAP = 0x80000000;
    public const uint PAGE_TARGETS_NO_UPDATE = 0x40000000;
    public const uint PAGE_TARGETS_INVALID = 0x40000000;
    public const uint PAGE_ENCLAVE_UNVALIDATED = 0x20000000;
    public const uint PAGE_ENCLAVE_MASK = 0x10000000;
    public const uint PAGE_ENCLAVE_DECOMMIT = 0x10000000;
    public const uint PAGE_ENCLAVE_SS_FIRST = 0x10000001;
    public const uint PAGE_ENCLAVE_SS_REST = 0x10000002;
}