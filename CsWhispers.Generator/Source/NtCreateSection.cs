using System.Runtime.InteropServices;

namespace CsWhispers;

public static unsafe partial class Syscalls
{
    private const string ZwCreateSectionHash = "12C4C6E5EB9B290330CA3A7E5D43D0FA";

    public static NTSTATUS NtCreateSection(
        HANDLE* sectionHandle,
        uint desiredAccess,
        [Optional] OBJECT_ATTRIBUTES* objectAttributes,
        [Optional] long* maximumSize,
        uint sectionPageProtection,
        uint allocationAttributes,
        [Optional] HANDLE fileHandle)
    {
        var stub = GetSyscallStub(ZwCreateSectionHash);

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

            var ntCreateSection = Marshal.GetDelegateForFunctionPointer<ZwCreateSection>(ptr);

            var status = ntCreateSection(
                sectionHandle,
                desiredAccess,
                objectAttributes,
                maximumSize,
                sectionPageProtection,
                allocationAttributes,
                fileHandle);

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
    private delegate NTSTATUS ZwCreateSection(
        HANDLE* sectionHandle,
        uint desiredAccess,
        [Optional] OBJECT_ATTRIBUTES* objectAttributes,
        [Optional] long* maximumSize,
        uint sectionPageProtection,
        uint allocationAttributes,
        [Optional] HANDLE fileHandle);
}

public static partial class Constants
{
    public const int SECTION_QUERY = 1;
    public const int SECTION_MAP_WRITE = 2;
    public const int SECTION_MAP_READ = 4;
    public const int SECTION_MAP_EXECUTE = 8;
    public const int SECTION_EXTEND_SIZE = 16;
    public const int SECTION_MAP_EXECUTE_EXPLICIT = 32;

    public const uint SECTION_ALL_ACCESS = STANDARD_RIGHTS_REQUIRED | SECTION_QUERY |
                                           SECTION_MAP_WRITE | SECTION_MAP_READ |
                                           SECTION_MAP_EXECUTE | SECTION_EXTEND_SIZE;
    
    public const uint SEC_COMMIT = 0x8000000;
    public const uint SEC_IMAGE = 0x1000000;
    public const uint SEC_IMAGE_NO_EXECUTE = 0x11000000;
    public const uint SEC_LARGE_PAGES = 0x80000000;
    public const uint SEC_NOCACHE = 0x10000000;
    public const uint SEC_RESERVE = 0x4000000;
    public const uint SEC_WRITECOMBINE = 0x40000000;
}