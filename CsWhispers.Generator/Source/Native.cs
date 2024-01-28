using System.Runtime.InteropServices;

namespace DInvoke;

public static unsafe partial class Native
{
    private const string NtDll = "ntdll.dll";

    public static NTSTATUS NtProtectVirtualMemory(
        HANDLE processHandle,
        ref IntPtr baseAddress,
        ref IntPtr regionSize,
        uint newProtect,
        out uint oldProtect)
    {
        object[] parameters = [processHandle, baseAddress, regionSize, newProtect, (uint)0];

        var status = Generic.DynamicApiInvoke<NTSTATUS>(
            NtDll, 
            "NtProtectVirtualMemory",
            typeof(NtProtectVirtualMemoryD),
            ref parameters);

        oldProtect = (uint)parameters[4];
        return status;
    }

    public static void RtlInitUnicodeString(
        UNICODE_STRING* destination,
        [MarshalAs(UnmanagedType.LPWStr)] string source)
    {
        var hFunction = Generic.GetLibraryAddress(NtDll, "RtlInitUnicodeString");
        var rtlInitUnicodeString = Marshal.GetDelegateForFunctionPointer<RtlInitUnicodeStringD>(hFunction);

        rtlInitUnicodeString(
            destination,
            source);
    }

    public static NTSTATUS LdrLoadDll(UNICODE_STRING* moduleFileName, HANDLE* moduleHandle)
    {
        var hFunction = Generic.GetLibraryAddress(NtDll, "LdrLoadDll");
        var ldrLoadDll = Marshal.GetDelegateForFunctionPointer<LdrLoadDllD>(hFunction);

        return ldrLoadDll(
            null,
            0,
            moduleFileName,
            moduleHandle);
    }

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate NTSTATUS NtProtectVirtualMemoryD(
        HANDLE processHandle,
        ref IntPtr baseAddress,
        ref IntPtr regionSize,
        uint newProtect,
        ref uint oldProtect);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate void RtlInitUnicodeStringD(
        UNICODE_STRING* destinationString,
        [MarshalAs(UnmanagedType.LPWStr)] string sourceString);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate NTSTATUS LdrLoadDllD(
        [Optional] char* pathToFile,
        [Optional] uint flags,
        UNICODE_STRING* moduleFileName,
        HANDLE* moduleHandle);
}