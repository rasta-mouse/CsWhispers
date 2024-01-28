namespace CsWhispers;

public unsafe struct OBJECT_ATTRIBUTES
{
    public uint Length;
    public HANDLE RootDirectory;
    public UNICODE_STRING* ObjectName;
    public uint Attributes;
    public void* SecurityDescriptor;
    public void* SecurityQualityOfService;
}

public static partial class Constants
{
    public const int OBJ_HANDLE_TAGBITS = 3;
    public const int OBJ_INHERIT = 2;
    public const int OBJ_PERMANENT = 16;
    public const int OBJ_EXCLUSIVE = 32;
    public const int OBJ_CASE_INSENSITIVE = 64;
    public const int OBJ_OPENIF = 128;
    public const int OBJ_OPENLINK = 256;
    public const int OBJ_KERNEL_HANDLE = 512;
    public const int OBJ_FORCE_ACCESS_CHECK = 1024;
    public const int OBJ_IGNORE_IMPERSONATED_DEVICEMAP = 2048;
    public const int OBJ_DONT_REPARSE = 4096;
    public const int OBJ_VALID_ATTRIBUTES = 8178;
}