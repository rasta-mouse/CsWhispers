namespace CsWhispers;

public static partial class Constants
{
    public const uint DELETE = 65536;
    public const uint READ_CONTROL = 131072;
    public const uint SYNCHRONIZE = 1048576;
    public const uint WRITE_DAC = 262144;
    public const uint WRITE_OWNER = 524288;

    public const uint GENERIC_READ = 2147483648;
    public const uint GENERIC_WRITE = 1073741824;
    public const uint GENERIC_EXECUTE = 536870912;
    public const uint GENERIC_ALL = 268435456;

    public const uint STANDARD_RIGHTS_READ = 131072;
    public const uint STANDARD_RIGHTS_WRITE = 131072;
    public const uint STANDARD_RIGHTS_EXECUTE = 131072;
    public const uint STANDARD_RIGHTS_REQUIRED = 983040;
    public const uint STANDARD_RIGHTS_ALL = 2031616;

    public const uint THREAD_TERMINATE = 0x00000001;
    public const uint THREAD_SUSPEND_RESUME = 0x00000002;
    public const uint THREAD_GET_CONTEXT = 0x00000008;
    public const uint THREAD_SET_CONTEXT = 0x00000010;
    public const uint THREAD_SET_INFORMATION = 0x00000020;
    public const uint THREAD_QUERY_INFORMATION = 0x00000040;
    public const uint THREAD_SET_THREAD_TOKEN = 0x00000080;
    public const uint THREAD_IMPERSONATE = 0x00000100;
    public const uint THREAD_DIRECT_IMPERSONATION = 0x00000200;
    public const uint THREAD_SET_LIMITED_INFORMATION = 0x00000400;
    public const uint THREAD_QUERY_LIMITED_INFORMATION = 0x00000800;
    public const uint THREAD_RESUME = 0x00001000;
    public const uint THREAD_ALL_ACCESS = 0x001FFFFF;
    public const uint THREAD_DELETE = 0x00010000;
    public const uint THREAD_READ_CONTROL = 0x00020000;
    public const uint THREAD_WRITE_DAC = 0x00040000;
    public const uint THREAD_WRITE_OWNER = 0x00080000;
    public const uint THREAD_SYNCHRONIZE = 0x00100000;
    public const uint THREAD_STANDARD_RIGHTS_REQUIRED = 0x000F0000;
}