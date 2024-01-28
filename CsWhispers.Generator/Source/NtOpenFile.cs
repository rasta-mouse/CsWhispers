using System.Runtime.InteropServices;

namespace CsWhispers;

public static unsafe partial class Syscalls
{
    private const string ZwOpenFileHash = "568DFAF213A08F28C9D58D1234D4218A";

    public static NTSTATUS NtOpenFile(
        HANDLE* fileHandle,
        uint desiredAccess,
        OBJECT_ATTRIBUTES* objectAttributes,
        IO_STATUS_BLOCK* ioStatusBlock,
        uint shareAccess,
        uint openOptions)
    {
        var stub = GetSyscallStub(ZwOpenFileHash);

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

            var ntOpenFile = Marshal.GetDelegateForFunctionPointer<ZwOpenFile>(ptr);

            var status = ntOpenFile(
                fileHandle,
                desiredAccess,
                objectAttributes,
                ioStatusBlock,
                shareAccess,
                openOptions);

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
    private delegate NTSTATUS ZwOpenFile(
        HANDLE* fileHandle,
        uint desiredAccess,
        OBJECT_ATTRIBUTES* objectAttributes,
        IO_STATUS_BLOCK* ioStatusBlock,
        uint shareAccess,
        uint openOptions);
}

public static partial class Constants
{
    public const int FILE_READ_DATA = 1;
    public const int FILE_WRITE_DATA = 2;
    public const int FILE_APPEND_DATA = 4;
    public const int FILE_READ_EA = 8;
    public const int FILE_WRITE_EA = 16;
    public const int FILE_EXECUTE = 32;
    public const int FILE_READ_ATTRIBUTES = 128;
    public const int FILE_WRITE_ATTRIBUTES = 256;
    
    public const int FILE_SHARE_READ = 1;
    public const int FILE_SHARE_WRITE = 2;
    public const int FILE_SHARE_DELETE = 4;
    
    public const int FILE_DIRECTORY_FILE = 1;
    public const int FILE_WRITE_THROUGH = 2;
    public const int FILE_SEQUENTIAL_ONLY = 4;
    public const int FILE_NO_INTERMEDIATE_BUFFERING = 8;
    public const int FILE_SYNCHRONOUS_IO_ALERT = 16;
    public const int FILE_SYNCHRONOUS_IO_NONALERT = 32;
    public const int FILE_NON_DIRECTORY_FILE = 64;
    public const int FILE_CREATE_TREE_CONNECTION = 128;
    public const int FILE_COMPLETE_IF_OPLOCKED = 256;
    public const int FILE_NO_EA_KNOWLEDGE = 512;
    public const int FILE_OPEN_REMOTE_INSTANCE = 1024;
    public const int FILE_RANDOM_ACCESS = 2048;
    public const int FILE_DELETE_ON_CLOSE = 4096;
    public const int FILE_OPEN_BY_FILE_ID = 8192;
    public const int FILE_OPEN_FOR_BACKUP_INTENT = 16384;
    public const int FILE_NO_COMPRESSION = 32768;
    public const int FILE_OPEN_REQUIRING_OPLOCK = 65536;
    public const int FILE_DISALLOW_EXCLUSIVE = 131072;
    public const int FILE_SESSION_AWARE = 262144;
    public const int FILE_RESERVE_OPFILTER = 1048576;
    public const int FILE_OPEN_REPARSE_POINT = 2097152;
    public const int FILE_OPEN_NO_RECALL = 4194304;
    public const int FILE_OPEN_FOR_FREE_SPACE_QUERY = 8388608;
    public const int FILE_CONTAINS_EXTENDED_CREATE_INFORMATION = 268435456;
}