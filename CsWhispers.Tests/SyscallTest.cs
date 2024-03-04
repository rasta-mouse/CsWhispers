using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.CompilerServices;

namespace CsWhispers.Tests;

public sealed class SyscallTest
{
    [Fact]
    public static unsafe void OpenProcess_Hooked()
    {
        IntPtr pNtOpenProcess = Generic.GetExportAddress(Generic.GetLoadedModuleAddress("ntdll.dll"), "NtOpenProcess");
        IntPtr ogNtOpenProcess = pNtOpenProcess;

        var size = 0;
        if (IntPtr.Size == 8)
            size = 0x14;
        else
            size = 0xC;

        byte[] patch = new byte[size];
        byte[] ogBytes = new byte[size];

        uint OldProtect = 0;
        uint RegionSize = 0x14;
        NTSTATUS status;
        status = NtProtectVirtualMemory(
            new HANDLE((IntPtr)(-1)),
            &pNtOpenProcess,
            &RegionSize,
            PAGE_EXECUTE_READWRITE,
            &OldProtect);

        pNtOpenProcess = ogNtOpenProcess;

        Marshal.Copy(pNtOpenProcess, ogBytes, 0, size);
        Marshal.Copy(patch, 0, pNtOpenProcess, size);

        using var self = Process.GetCurrentProcess();

        HANDLE hProcess;
        OBJECT_ATTRIBUTES oa;

        // IDK WHY WOW64 NEEDS THIS TO BE FILLED I WASTED 5 HOURS ON THIS
        if (IntPtr.Size == 4)
        {
            oa.Length = (uint)sizeof(OBJECT_ATTRIBUTES);
        }
        CLIENT_ID cid = new()
        {
            UniqueProcess = new((IntPtr)self.Id)
        };

        status = NtOpenProcess(
            &hProcess,
            PROCESS_ALL_ACCESS,
            &oa,
            &cid);

        Assert.Equal(NTSTATUS.Severity.Success, status.SeverityCode);
        Assert.NotEqual(HANDLE.Null, hProcess);

        Marshal.Copy(ogBytes, 0, pNtOpenProcess, size);
    }

    [Fact]
    public static unsafe void OpenProcess()
    {
        using var self = Process.GetCurrentProcess();
        
        NTSTATUS status;
        HANDLE hProcess;
        OBJECT_ATTRIBUTES oa;

        CLIENT_ID cid = new()
        {
            UniqueProcess = new((IntPtr)self.Id)
        };
        // IDK WHY WOW64 NEEDS THIS TO BE FILLED I WASTED 5 HOURS ON THIS
        if (IntPtr.Size == 4)
        {
            oa.Length = (uint)sizeof(OBJECT_ATTRIBUTES);
        }
        status = NtOpenProcess(
            &hProcess,
            PROCESS_ALL_ACCESS,
            &oa,
            &cid);

        Assert.Equal(NTSTATUS.Severity.Success, status.SeverityCode);
        Assert.NotEqual(HANDLE.Null, hProcess);
    }

    [Fact]
    public static unsafe void AllocateVirtualMemory()
    {

        NTSTATUS status;
        HANDLE hProcess = new((IntPtr)(-1));
        void* BaseAddress = (void*)0;
        uint RegionSize = 1024;


        status = NtAllocateVirtualMemory(
            hProcess,
            &BaseAddress,
            0,
            &RegionSize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE);

        Assert.Equal(NTSTATUS.Severity.Success, status.SeverityCode);
        Assert.NotEqual(IntPtr.Zero, (IntPtr)BaseAddress);
    }

    [Fact]
    public static unsafe void ProtectVirtualMemory()
    {

        NTSTATUS status;
        HANDLE hProcess = new((IntPtr)(-1));
        void* BaseAddress = (void*)0;
        uint RegionSize = 1024;


        status = NtAllocateVirtualMemory(
            hProcess,
            &BaseAddress,
            0,
            &RegionSize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE);

        Assert.Equal(NTSTATUS.Severity.Success, status.SeverityCode);
        Assert.NotEqual(IntPtr.Zero, (IntPtr)BaseAddress);

        uint OldProtect = 0;
        status = NtProtectVirtualMemory(
            hProcess,
            &BaseAddress,
            &RegionSize,
            PAGE_READWRITE,
            &OldProtect);

        Assert.Equal(NTSTATUS.Severity.Success, status.SeverityCode);
        Assert.Equal(OldProtect, PAGE_EXECUTE_READWRITE);

    }

    [Fact]
    public static unsafe void FreeVirtualMemory()
    {

        NTSTATUS status;
        HANDLE hProcess = new((IntPtr)(-1));
        void* BaseAddress = (void*)0;
        uint RegionSize = 1024;


        status = NtAllocateVirtualMemory(
            hProcess,
            &BaseAddress,
            0,
            &RegionSize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE);

        Assert.Equal(NTSTATUS.Severity.Success, status.SeverityCode);
        Assert.NotEqual(IntPtr.Zero, (IntPtr)BaseAddress);

        RegionSize = 0;
        status = NtFreeVirtualMemory(
            hProcess,
            &BaseAddress,
            &RegionSize,
            MEM_RELEASE);

        Assert.Equal(NTSTATUS.Severity.Success, status.SeverityCode);
        Assert.NotEqual((uint)0, RegionSize);

    }

    [Fact]
    public static unsafe void WriteVirtualMemory()
    {

        NTSTATUS status;
        HANDLE hProcess = new((IntPtr)(-1));
        void* BaseAddress = (void*)0;
        uint RegionSize = 1024;

        status = NtAllocateVirtualMemory(
            hProcess,
            &BaseAddress,
            0,
            &RegionSize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE);

        Assert.Equal(NTSTATUS.Severity.Success, status.SeverityCode);
        Assert.NotEqual(IntPtr.Zero, (IntPtr)BaseAddress);

        byte[] Bytes = { 0x90, 0x90, 0x90, 0xc3 };
        uint Length = (uint)Bytes.Length;
        uint BytesWritten = 0;

        fixed (byte* pBytes = Bytes)
        {
            status = NtWriteVirtualMemory(
                hProcess,
                BaseAddress,
                pBytes,
                Length,
                &BytesWritten);
        }
        Assert.Equal(NTSTATUS.Severity.Success, status.SeverityCode);
        Assert.Equal(BytesWritten, Length);

    }

    [Fact]
    public static unsafe void ReadVirtualMemory()
    {

        NTSTATUS status;
        HANDLE hProcess = new((IntPtr)(-1));
        void* BaseAddress = (void*)0;
        uint RegionSize = 1024;


        status = NtAllocateVirtualMemory(
            hProcess,
            &BaseAddress,
            0,
            &RegionSize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE);

        Assert.Equal(NTSTATUS.Severity.Success, status.SeverityCode);
        Assert.NotEqual(IntPtr.Zero, (IntPtr)BaseAddress);

        byte[] BytesWrite = { 0x90, 0x90, 0x90, 0xc3 };
        byte[] BytesRead = new byte[5];
        uint Length = (uint)BytesWrite.Length;
        uint BytesWritten = 0;
        fixed (byte* pBytesWrite = BytesWrite, pBytesRead = BytesRead)
        {
            status = NtWriteVirtualMemory(
                hProcess,
                BaseAddress,
                pBytesWrite,
                Length,
                &BytesWritten);

            Assert.Equal(NTSTATUS.Severity.Success, status.SeverityCode);
            Assert.Equal(BytesWritten, Length);

            uint BytesReaded = 0;
            status = NtReadVirtualMemory(
                hProcess,
                BaseAddress,
                pBytesRead,
                Length,
                &BytesReaded);

            Assert.Equal(NTSTATUS.Severity.Success, status.SeverityCode);
            Assert.Equal(*(uint*)pBytesRead, *(uint*)pBytesWrite);
            Assert.Equal(Length, BytesReaded);
        }

    }

    [Fact]
    public static unsafe void QueryVirtualMemory()
    {

        NTSTATUS status;
        HANDLE hProcess = new((IntPtr)(-1));
        void* BaseAddress = (void*)0;
        uint RegionSize = 1024;


        status = NtAllocateVirtualMemory(
            hProcess,
            &BaseAddress,
            0,
            &RegionSize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE);

        Assert.Equal(NTSTATUS.Severity.Success, status.SeverityCode);
        Assert.NotEqual(IntPtr.Zero, (IntPtr)BaseAddress);

        MEMORY_BASIC_INFORMATION Information = default;
        uint Length = (uint)sizeof(MEMORY_BASIC_INFORMATION);
        status = NtQueryVirtualMemory(
            hProcess,
            BaseAddress,
            MEMORY_INFORMATION_CLASS.MemoryBasicInformation,
            &Information,
            (uint)sizeof(MEMORY_BASIC_INFORMATION),
            &Length
            );

        Assert.Equal(NTSTATUS.Severity.Success, status.SeverityCode);
        Assert.Equal((uint)sizeof(MEMORY_BASIC_INFORMATION), Length);
        Assert.Equal(Information.AllocationProtect, PAGE_EXECUTE_READWRITE);
    }

    [Fact]
    public static unsafe void CreateThreadEx()
    {

        NTSTATUS status;
        HANDLE hProcess = new((IntPtr)(-1));
        void* BaseAddress = (void*)0;
        uint RegionSize = 1024;


        status = NtAllocateVirtualMemory(
            hProcess,
            &BaseAddress,
            0,
            &RegionSize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE);

        Assert.Equal(NTSTATUS.Severity.Success, status.SeverityCode);
        Assert.NotEqual(IntPtr.Zero, (IntPtr)BaseAddress);

        byte[] Bytes = { 0x90, 0x90, 0x90, 0xc3 };
        uint Length = (uint)Bytes.Length;
        uint BytesWritten = 0;
        fixed (byte* pBytes = Bytes)
        {
            status = NtWriteVirtualMemory(
                 hProcess,
                 BaseAddress,
                 pBytes,
                 Length,
                 &BytesWritten);

            Assert.Equal(NTSTATUS.Severity.Success, status.SeverityCode);
            Assert.Equal(BytesWritten, Length);

            HANDLE hThread;
            USER_THREAD_START_ROUTINE StartAddress = (USER_THREAD_START_ROUTINE)Marshal.GetDelegateForFunctionPointer<USER_THREAD_START_ROUTINE>((IntPtr)BaseAddress);
            status = NtCreateThreadEx(
                &hThread,
                THREAD_ALL_ACCESS,
                (OBJECT_ATTRIBUTES*)IntPtr.Zero,
                hProcess,
                StartAddress,
                (void*)IntPtr.Zero,
                0,
                0,
                0,
                0,
                (PS_ATTRIBUTE_LIST*)0);

            Assert.Equal(NTSTATUS.Severity.Success, status.SeverityCode);
            Assert.NotEqual(IntPtr.Zero, hThread.Value);
        }
    }

    [Fact]
    public static unsafe void OpenFile()
    {

        string devicePath = "\\??\\C:\\Windows\\System32\\ntdll.dll";

        fixed (char* pDevicePath = devicePath)
        {
            NTSTATUS status;
            HANDLE hFile;
            UNICODE_STRING str = new()
            {
                Length = (ushort)(devicePath.Length * 2),
                MaximumLength = (ushort)(devicePath.Length * 2),
                Buffer = new PWSTR(pDevicePath)
            };
            OBJECT_ATTRIBUTES Attributes = new()
            {
                Length = (uint)sizeof(OBJECT_ATTRIBUTES),
                RootDirectory = new HANDLE(IntPtr.Zero),
                ObjectName = &str,
                Attributes = OBJ_CASE_INSENSITIVE,
                SecurityDescriptor = (void*)0,
                SecurityQualityOfService = (void*)0,
            };
            IO_STATUS_BLOCK status_block;
            status = NtOpenFile(
                &hFile,
                GENERIC_READ,
                &Attributes,
                &status_block,
                FILE_SHARE_READ,
                0);

            Assert.Equal(NTSTATUS.Severity.Success, status.SeverityCode);
            Assert.NotEqual(HANDLE.Null, hFile);

        }

    }

    [Fact]
    public static unsafe void Close()
    {

        string devicePath = "\\??\\C:\\Windows\\System32\\ntdll.dll";

        fixed (char* pDevicePath = devicePath)
        {
            NTSTATUS status;
            HANDLE hFile;
            UNICODE_STRING str = new()
            {
                Length = (ushort)(devicePath.Length * 2),
                MaximumLength = (ushort)(devicePath.Length * 2),
                Buffer = new PWSTR(pDevicePath)
            };
            OBJECT_ATTRIBUTES Attributes = new()
            {
                Length = (uint)sizeof(OBJECT_ATTRIBUTES),
                RootDirectory = new HANDLE(IntPtr.Zero),
                ObjectName = &str,
                Attributes = OBJ_CASE_INSENSITIVE,
                SecurityDescriptor = (void*)0,
                SecurityQualityOfService = (void*)0,
            };
            IO_STATUS_BLOCK status_block;
            status = NtOpenFile(
                &hFile,
                GENERIC_READ,
                &Attributes,
                &status_block,
                FILE_SHARE_READ,
                0);

            Assert.Equal(NTSTATUS.Severity.Success, status.SeverityCode);
            Assert.NotEqual(HANDLE.Null, hFile);

            status = NtClose(hFile);
            Assert.Equal(NTSTATUS.Severity.Success, status.SeverityCode);
        }
    }

    [Fact]
    public static unsafe void CreateSection()
    {

        string devicePath = "\\??\\C:\\Windows\\System32\\ntdll.dll";

        fixed (char* pDevicePath = devicePath)
        {
            NTSTATUS status;
            HANDLE hFile;
            UNICODE_STRING str = new()
            {
                Length = (ushort)(devicePath.Length * 2),
                MaximumLength = (ushort)(devicePath.Length * 2),
                Buffer = new PWSTR(pDevicePath)
            };
            OBJECT_ATTRIBUTES Attributes = new()
            {
                Length = (uint)sizeof(OBJECT_ATTRIBUTES),
                RootDirectory = new HANDLE(IntPtr.Zero),
                ObjectName = &str,
                Attributes = OBJ_CASE_INSENSITIVE,
                SecurityDescriptor = (void*)0,
                SecurityQualityOfService = (void*)0,
            };
            IO_STATUS_BLOCK status_block;
            status = NtOpenFile(
                &hFile,
                GENERIC_READ,
                &Attributes,
                &status_block,
                FILE_SHARE_READ,
                0);

            Assert.Equal(NTSTATUS.Severity.Success, status.SeverityCode);
            Assert.NotEqual(HANDLE.Null, hFile);

            HANDLE hSection;
            status = NtCreateSection(
                &hSection,
                SECTION_MAP_READ,
                (OBJECT_ATTRIBUTES*)0,
                (long*)0,
                PAGE_READONLY,
                SEC_IMAGE,
                hFile);

            Assert.Equal(NTSTATUS.Severity.Success, status.SeverityCode);
            Assert.NotEqual(HANDLE.Null, hSection);
        }

    }

    [Fact]
    public static unsafe void MapViewOfSection()
    {

        string devicePath = "\\??\\C:\\Windows\\System32\\ntdll.dll";

        fixed (char* pDevicePath = devicePath)
        {
            NTSTATUS status;
            HANDLE hFile;
            UNICODE_STRING str = new()
            {
                Length = (ushort)(devicePath.Length * 2),
                MaximumLength = (ushort)(devicePath.Length * 2),
                Buffer = new PWSTR(pDevicePath)
            };
            OBJECT_ATTRIBUTES Attributes = new()
            {
                Length = (uint)sizeof(OBJECT_ATTRIBUTES),
                RootDirectory = new HANDLE(IntPtr.Zero),
                ObjectName = &str,
                Attributes = OBJ_CASE_INSENSITIVE,
                SecurityDescriptor = (void*)0,
                SecurityQualityOfService = (void*)0,
            };
            IO_STATUS_BLOCK status_block;
            status = NtOpenFile(
                &hFile,
                GENERIC_READ,
                &Attributes,
                &status_block,
                FILE_SHARE_READ,
                0);

            Assert.Equal(NTSTATUS.Severity.Success, status.SeverityCode);
            Assert.NotEqual(HANDLE.Null, hFile);

            HANDLE hSection;
            status = NtCreateSection(
                &hSection,
                SECTION_MAP_READ,
                (OBJECT_ATTRIBUTES*)0,
                (long*)0,
                PAGE_READONLY,
                SEC_IMAGE,
                hFile);

            Assert.Equal(NTSTATUS.Severity.Success, status.SeverityCode);
            Assert.NotEqual(HANDLE.Null, hSection);

            long offset = 0;
            IntPtr BaseAddress;
            nuint ViewSize = 0;
            status = NtMapViewOfSection(
                hSection,
                new HANDLE((IntPtr)(-1)),
                &BaseAddress,
                0,
                0,
                &offset,
                &ViewSize,
                SECTION_INHERIT.ViewShare,
                0,
                PAGE_READONLY);

            Assert.Equal(0x40000003, status.Value);
            Assert.NotEqual(IntPtr.Zero, BaseAddress);
        }
    }

    [Fact]
    public static unsafe void UnmapViewOfSection()
    {

        string devicePath = "\\??\\C:\\Windows\\System32\\ntdll.dll";

        HANDLE hProcess = new HANDLE((IntPtr)(-1));
        fixed (char* pDevicePath = devicePath)
        {
            NTSTATUS status;
            HANDLE hFile;
            UNICODE_STRING str = new()
            {
                Length = (ushort)(devicePath.Length * 2),
                MaximumLength = (ushort)(devicePath.Length * 2),
                Buffer = new PWSTR(pDevicePath)
            };
            OBJECT_ATTRIBUTES Attributes = new()
            {
                Length = (uint)sizeof(OBJECT_ATTRIBUTES),
                RootDirectory = new HANDLE(IntPtr.Zero),
                ObjectName = &str,
                Attributes = OBJ_CASE_INSENSITIVE,
                SecurityDescriptor = (void*)0,
                SecurityQualityOfService = (void*)0,
            };
            IO_STATUS_BLOCK status_block;
            status = NtOpenFile(
                &hFile,
                GENERIC_READ,
                &Attributes,
                &status_block,
                FILE_SHARE_READ,
                0);

            Assert.Equal(NTSTATUS.Severity.Success, status.SeverityCode);
            Assert.NotEqual(HANDLE.Null, hFile);

            HANDLE hSection;
            status = NtCreateSection(
                &hSection,
                SECTION_MAP_READ,
                (OBJECT_ATTRIBUTES*)0,
                (long*)0,
                PAGE_READONLY,
                SEC_IMAGE,
                hFile);

            Assert.Equal(NTSTATUS.Severity.Success, status.SeverityCode);
            Assert.NotEqual(HANDLE.Null, hSection);

            long offset = 0;
            IntPtr BaseAddress;
            nuint ViewSize = 0;
            status = NtMapViewOfSection(
                hSection,
                hProcess,
                &BaseAddress,
                0,
                0,
                &offset,
                &ViewSize,
                SECTION_INHERIT.ViewShare,
                0,
                PAGE_READONLY);

            Assert.Equal(0x40000003, status.Value);
            Assert.NotEqual(IntPtr.Zero, BaseAddress);

            status = NtUnmapViewOfSection(
                hProcess,
                (void*)BaseAddress);

            Assert.Equal(NTSTATUS.Severity.Success, status.SeverityCode);

            MEMORY_BASIC_INFORMATION Information = default;
            uint Length = (uint)sizeof(MEMORY_BASIC_INFORMATION);
            status = NtQueryVirtualMemory(
                hProcess,
                (void*)BaseAddress,
                MEMORY_INFORMATION_CLASS.MemoryBasicInformation,
                &Information,
                (uint)sizeof(MEMORY_BASIC_INFORMATION),
                &Length
                );

            Assert.Equal(NTSTATUS.Severity.Success, status.SeverityCode);
            Assert.Equal((uint)sizeof(MEMORY_BASIC_INFORMATION), Length);
            Assert.Equal(Information.State, MEM_FREE);

        }
    }
}