using System.Runtime.InteropServices;

namespace CsWhispers;

public static unsafe partial class Syscalls
{
    private const string ZwMapViewOfSectionHash = "C72A45E418708097B7D23865D6187D5E";

    public static NTSTATUS NtMapViewOfSection(
        HANDLE sectionHandle,
        HANDLE processHandle,
        void* baseAddress,
        nuint zeroBits,
        nuint commitSize,
        [Optional] long* sectionOffset,
        nuint* viewSize,
        SECTION_INHERIT inheritDisposition,
        uint allocationType,
        uint win32Protect)
    {
        var stub = GetSyscallStub(ZwMapViewOfSectionHash);

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

            var ntMapViewOfSection = Marshal.GetDelegateForFunctionPointer<ZwMapViewOfSection>(ptr);
            
            var status = ntMapViewOfSection(
                sectionHandle, 
                processHandle,
                baseAddress, 
                zeroBits, 
                commitSize,
                sectionOffset,
                viewSize,
                inheritDisposition,
                allocationType, 
                win32Protect);

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
    private delegate NTSTATUS ZwMapViewOfSection(
        HANDLE sectionHandle,
        HANDLE processHandle,
        void* baseAddress,
        nuint zeroBits,
        nuint commitSize,
        [Optional] long* sectionOffset,
        nuint* viewSize,
        SECTION_INHERIT inheritDisposition,
        uint allocationType,
        uint win32Protect);
}