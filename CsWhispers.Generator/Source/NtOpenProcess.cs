using System.Runtime.InteropServices;

namespace CsWhispers;

public static unsafe partial class Syscalls
{
    private const string ZwOpenProcessHash = "00B6CA92B16374B1C81FC54DFE03DF52";
    
    private static int NtOpenProcessJit() {  return 5; }

    public static NTSTATUS NtOpenProcess(
        HANDLE* processHandle,
        uint desiredAccess,
        OBJECT_ATTRIBUTES* objectAttributes,
        CLIENT_ID* clientId)
    {
        var stub = GetSyscallStub(ZwOpenProcessHash);
        fixed (byte* buffer = stub)
        {
            IntPtr ptr = PrepareJit(nameof(NtOpenProcessJit), buffer, stub.Length);
            
            var ntOpenProcess = Marshal.GetDelegateForFunctionPointer<ZwOpenProcess>(ptr);

            var status = ntOpenProcess(
                processHandle, 
                desiredAccess, 
                objectAttributes,
                clientId);

            return status;
        }
    }
    
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate NTSTATUS ZwOpenProcess(
        HANDLE* processHandle,
        uint desiredAccess,
        OBJECT_ATTRIBUTES* objectAttributes,
        CLIENT_ID* clientId);
}

public static partial class Constants
{
    public const uint PROCESS_TERMINATE = 0x00000001;
    public const uint PROCESS_CREATE_THREAD = 0x00000002;
    public const uint PROCESS_SET_SESSIONID = 0x00000004;
    public const uint PROCESS_VM_OPERATION = 0x00000008;
    public const uint PROCESS_VM_READ = 0x00000010;
    public const uint PROCESS_VM_WRITE = 0x00000020;
    public const uint PROCESS_DUP_HANDLE = 0x00000040;
    public const uint PROCESS_CREATE_PROCESS = 0x00000080;
    public const uint PROCESS_SET_QUOTA = 0x00000100;
    public const uint PROCESS_SET_INFORMATION = 0x00000200;
    public const uint PROCESS_QUERY_INFORMATION = 0x00000400;
    public const uint PROCESS_SUSPEND_RESUME = 0x00000800;
    public const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x00001000;
    public const uint PROCESS_SET_LIMITED_INFORMATION = 0x00002000;
    public const uint PROCESS_ALL_ACCESS = 0x001FFFFF;
    public const uint PROCESS_DELETE = 0x00010000;
    public const uint PROCESS_READ_CONTROL = 0x00020000;
    public const uint PROCESS_WRITE_DAC = 0x00040000;
    public const uint PROCESS_WRITE_OWNER = 0x00080000;
    public const uint PROCESS_SYNCHRONIZE = 0x00100000;
    public const uint PROCESS_STANDARD_RIGHTS_REQUIRED = 0x000F0000;
}