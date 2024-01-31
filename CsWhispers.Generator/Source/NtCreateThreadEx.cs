using System.Runtime.InteropServices;

namespace CsWhispers;

public static unsafe partial class Syscalls
{
    private const string ZwCreateThreadExHash = "434AE47989589026C54B874E5D12D365";
    
    public static NTSTATUS NtCreateThreadEx(
        HANDLE* threadHandle,
        uint desiredAccess,
        [Optional] OBJECT_ATTRIBUTES* objectAttributes,
        HANDLE processHandle,
        USER_THREAD_START_ROUTINE startRoutine,
        [Optional] void* argument,
        uint createFlags,
        nuint zeroBits,
        nuint stackSize,
        nuint maximumStackSize,
        [Optional] PS_ATTRIBUTE_LIST* attributeList)
    {
        var stub = GetSyscallStub(ZwCreateThreadExHash);

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

            var ntCreateThreadEx = Marshal.GetDelegateForFunctionPointer<ZwCreateThreadEx>(ptr);

            var status = ntCreateThreadEx(
                threadHandle, 
                desiredAccess, 
                objectAttributes,
                processHandle, 
                startRoutine,
                argument, 
                createFlags, 
                zeroBits, 
                stackSize, 
                maximumStackSize, 
                attributeList);

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
    private delegate NTSTATUS ZwCreateThreadEx(
        HANDLE* threadHandle,
        uint desiredAccess,
        [Optional] OBJECT_ATTRIBUTES* objectAttributes,
        HANDLE processHandle,
        USER_THREAD_START_ROUTINE startRoutine,
        [Optional] void* argument,
        uint createFlags,
        nuint zeroBits,
        nuint stackSize,
        nuint maximumStackSize,
        [Optional] PS_ATTRIBUTE_LIST* attributeList);
}

public static partial class Constants
{
    public const uint THREAD_CREATE_FLAGS_CREATE_SUSPENDED = 0x00000001;
    public const uint THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH = 0x00000002;
    public const uint THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER = 0x00000004;
    public const uint THREAD_CREATE_FLAGS_LOADER_WORKER = 0x00000010;
    public const uint THREAD_CREATE_FLAGS_SKIP_LOADER_INIT = 0x00000020;
    public const uint THREAD_CREATE_FLAGS_BYPASS_PROCESS_FREEZE = 0x00000040;
}