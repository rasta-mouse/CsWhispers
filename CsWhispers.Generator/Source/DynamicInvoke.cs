using System.Diagnostics;
using System.Runtime.InteropServices;

namespace DInvoke;

public static partial class Generic
{
    /// <summary>
    /// Dynamically invoke an arbitrary function from a DLL, providing its name, function prototype, and arguments.
    /// </summary>
    /// <author>The Wover (@TheRealWover)</author>
    /// <param name="dllName">Name of the DLL.</param>
    /// <param name="functionName">Name of the function.</param>
    /// <param name="functionDelegateType">Prototype for the function, represented as a Delegate object.</param>
    /// <param name="parameters">Parameters to pass to the function. Can be modified if function uses call by reference.</param>
    /// <param name="canLoadFromDisk">Whether the DLL may be loaded from disk if it is not already loaded. Default is false.</param>
    /// <param name="resolveForwards">Whether or not to resolve export forwards. Default is true.</param>
    /// <returns>Object returned by the function. Must be unmarshalled by the caller.</returns>
    public static T DynamicApiInvoke<T>(string dllName, string functionName, Type functionDelegateType, ref object[] parameters, bool canLoadFromDisk = false, bool resolveForwards = true)
    {
        var pFunction = GetLibraryAddress(dllName, functionName, canLoadFromDisk, resolveForwards);
        return DynamicFunctionInvoke<T>(pFunction, functionDelegateType, ref parameters);
    }
    
    /// <summary>
    /// Dynamically invokes an arbitrary function from a pointer. Useful for manually mapped modules or loading/invoking unmanaged code from memory.
    /// </summary>
    /// <author>The Wover (@TheRealWover)</author>
    /// <param name="functionPointer">A pointer to the unmanaged function.</param>
    /// <param name="functionDelegateType">Prototype for the function, represented as a delegate.</param>
    /// <param name="parameters">Arbitrary set of parameters to pass to the function.</param>
    /// <returns>Object returned by the function. Must be unmarshalled by the caller.</returns>
    public static T DynamicFunctionInvoke<T>(IntPtr functionPointer, Type functionDelegateType, ref object[] parameters)
    {
        var funcDelegate = Marshal.GetDelegateForFunctionPointer(functionPointer, functionDelegateType);
        return (T)funcDelegate.DynamicInvoke(parameters);
    }

    public static T DynamicAsmInvoke<T>(byte[] asmStub, Type functionDelegateType, ref object[] parameters)
    {
        unsafe
        {
            fixed (byte* buffer = asmStub)
            {
                var ptr = (IntPtr)buffer;
                var size = new IntPtr(asmStub.Length);

                Native.NtProtectVirtualMemory(
                    new HANDLE((IntPtr)(-1)),
                    ref ptr,
                    ref size,
                    0x00000040,
                    out var oldProtect);

                var result = DynamicFunctionInvoke<T>(ptr, functionDelegateType, ref parameters);

                Native.NtProtectVirtualMemory(
                    new HANDLE((IntPtr)(-1)),
                    ref ptr,
                    ref size,
                    oldProtect,
                    out _);

                return result;
            }
        }
    }

    /// <summary>
    /// Helper for getting the base address of a module loaded by the current process. This base
    /// address could be passed to GetProcAddress/LdrGetProcedureAddress or it could be used for
    /// manual export parsing. This function uses the .NET System.Diagnostics.Process class.
    /// </summary>
    /// <author>Ruben Boonen (@FuzzySec)</author>
    /// <param name="dllName">The name of the DLL (e.g. "ntdll.dll").</param>
    /// <returns>IntPtr base address of the loaded module or IntPtr.Zero if the module is not found.</returns>
    public static IntPtr GetLoadedModuleAddress(string dllName)
    {
        using var process = Process.GetCurrentProcess();

        foreach (ProcessModule module in process.Modules)
        {
            if (module.ModuleName.Equals(dllName, StringComparison.OrdinalIgnoreCase))
                return module.BaseAddress;
        }
            
        return IntPtr.Zero;
    }
    
    /// <summary>
    /// Helper for getting the pointer to a function from a DLL loaded by the process.
    /// </summary>
    /// <author>Ruben Boonen (@FuzzySec)</author>
    /// <param name="dllName">The name of the DLL (e.g. "ntdll.dll" or "C:\Windows\System32\ntdll.dll").</param>
    /// <param name="functionName">Name of the exported procedure.</param>
    /// <param name="canLoadFromDisk">Optional, indicates if the function can try to load the DLL from disk if it is not found in the loaded module list.</param>
    /// <param name="resolveForwards">Whether or not to resolve export forwards. Default is true.</param>
    /// <returns>IntPtr for the desired function.</returns>
    public static IntPtr GetLibraryAddress(string dllName, string functionName, bool canLoadFromDisk = false, bool resolveForwards = true)
    {
        var hModule = GetLoadedModuleAddress(dllName);
            
        if (hModule == IntPtr.Zero && canLoadFromDisk)
            hModule = LoadModuleFromDisk(dllName);

        return GetExportAddress(hModule, functionName, resolveForwards);
    }
    
    /// <summary>
    /// Given a module base address, resolve the address of a function by manually walking the module export table.
    /// </summary>
    /// <author>Ruben Boonen (@FuzzySec)</author>
    /// <param name="moduleBase">A pointer to the base address where the module is loaded in the current process.</param>
    /// <param name="exportName">The name of the export to search for (e.g. "NtAlertResumeThread").</param>
    /// <param name="resolveForwards">Whether or not to resolve export forwards. Default is true.</param>
    /// <returns>IntPtr for the desired function.</returns>
    public static IntPtr GetExportAddress(IntPtr moduleBase, string exportName, bool resolveForwards = true)
    {
        var functionPtr = IntPtr.Zero;
            
        try
        {
            // Traverse the PE header in memory
            var peHeader = Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + 0x3C));
            var optHeader = moduleBase.ToInt64() + peHeader + 0x18;
            var magic = Marshal.ReadInt16((IntPtr)optHeader);
            long pExport;
                
            if (magic == 0x010b) pExport = optHeader + 0x60;
            else pExport = optHeader + 0x70;

            var exportRva = Marshal.ReadInt32((IntPtr)pExport);
            var ordinalBase = Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + exportRva + 0x10));
            var numberOfNames = Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + exportRva + 0x18));
            var functionsRva = Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + exportRva + 0x1C));
            var namesRva = Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + exportRva + 0x20));
            var ordinalsRva = Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + exportRva + 0x24));
                
            for (var i = 0; i < numberOfNames; i++)
            {
                var functionName = Marshal.PtrToStringAnsi((IntPtr)(moduleBase.ToInt64() + Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + namesRva + i * 4))));
                if (string.IsNullOrWhiteSpace(functionName)) continue;
                if (!functionName.Equals(exportName, StringComparison.OrdinalIgnoreCase)) continue;
                    
                var functionOrdinal = Marshal.ReadInt16((IntPtr)(moduleBase.ToInt64() + ordinalsRva + i * 2)) + ordinalBase;
                    
                var functionRva = Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + functionsRva + 4 * (functionOrdinal - ordinalBase)));
                functionPtr = (IntPtr)((long)moduleBase + functionRva);
                        
                if (resolveForwards)
                    functionPtr = GetForwardAddress(functionPtr);

                break;
            }
        }
        catch
        {
            throw new InvalidOperationException("Failed to parse module exports.");
        }

        if (functionPtr == IntPtr.Zero)
            throw new MissingMethodException(exportName + ", export not found.");

        return functionPtr;
    }
    
    /// <summary>
    /// Check if an address to an exported function should be resolved to a forward. If so, return the address of the forward.
    /// </summary>
    /// <author>The Wover (@TheRealWover)</author>
    /// <param name="exportAddress">Function of an exported address, found by parsing a PE file's export table.</param>
    /// <param name="canLoadFromDisk">Optional, indicates if the function can try to load the DLL from disk if it is not found in the loaded module list.</param>
    /// <returns>IntPtr for the forward. If the function is not forwarded, return the original pointer.</returns>
    public static IntPtr GetForwardAddress(IntPtr exportAddress, bool canLoadFromDisk = false)
    {
        var functionPtr = exportAddress;
            
        try
        {
            var forwardNames = Marshal.PtrToStringAnsi(functionPtr);
            if (string.IsNullOrWhiteSpace(forwardNames)) return functionPtr;
                
            var values = forwardNames.Split('.');

            if (values.Length > 1)
            {
                var forwardModuleName = values[0];
                var forwardExportName = values[1];

                var apiSet = GetApiSetMapping();
                var lookupKey = forwardModuleName.Substring(0, forwardModuleName.Length - 2) + ".dll";
                    
                if (apiSet.TryGetValue(lookupKey, out var value))
                    forwardModuleName = value;
                else
                    forwardModuleName = forwardModuleName + ".dll";

                var hModule = GetPebLdrModuleEntry(forwardModuleName);
                    
                if (hModule == IntPtr.Zero && canLoadFromDisk)
                    hModule = LoadModuleFromDisk(forwardModuleName);
                    
                if (hModule != IntPtr.Zero)
                    functionPtr = GetExportAddress(hModule, forwardExportName);
            }
        }
        catch
        {
            // Do nothing, it was not a forward
        }
            
        return functionPtr;
    }
    
    /// <summary>
    /// This function uses dynamic assembly invocation to obtain a pointer to the PEB.
    /// __readgsqword(0x60) or __readfsdword(0x30)
    /// </summary>
    /// <returns>Base address of the PEB as an IntPtr.</returns>
    public static IntPtr GetPebAddress()
    {
        byte[] stub;
        
        if (IntPtr.Size == 8)
        {
            stub =
            [
                0x65, 0x48, 0x8B, 0x04, 0x25, 0x60,     // mov rax, qword ptr gs:[0x60]
                0x00, 0x00, 0x00,
                0xc3                                    // ret
            ];
        }
        else
        {
            stub =
            [
                0x64, 0xA1, 0x30, 0x00, 0x00, 0x00,     // mov eax,dword ptr fs:[30]
                0xC3                                    // ret
            ];
        }

        object[] parameters = [];
        
        return DynamicAsmInvoke<IntPtr>(
            stub,
            typeof(ReadGs),
            ref parameters);
    }
    
    /// <summary>
    /// Helper for getting the base address of a module loaded by the current process. This base
    /// address could be passed to GetProcAddress/LdrGetProcedureAddress or it could be used for
    /// manual export parsing. This function parses the _PEB_LDR_DATA structure.
    /// </summary>
    /// <author>Ruben Boonen (@FuzzySec)</author>
    /// <param name="dllName">The name of the DLL (e.g. "ntdll.dll").</param>
    /// <returns>IntPtr base address of the loaded module or IntPtr.Zero if the module is not found.</returns>
    public static IntPtr GetPebLdrModuleEntry(string dllName)
    {
        // Set function variables
        uint ldrDataOffset;
        uint inLoadOrderModuleListOffset;
            
        if (IntPtr.Size == 4)
        {
            ldrDataOffset = 0xc;
            inLoadOrderModuleListOffset = 0xC;
        }
        else
        {
            ldrDataOffset = 0x18;
            inLoadOrderModuleListOffset = 0x10;
        }

        // Get _PEB pointer
        var pPeb = GetPebAddress();

        // Get module InLoadOrderModuleList -> _LIST_ENTRY
        var pebLdrData = Marshal.ReadIntPtr((IntPtr)((ulong)pPeb + ldrDataOffset));
        var pInLoadOrderModuleList = (IntPtr)((ulong)pebLdrData + inLoadOrderModuleListOffset);
        var le = Marshal.PtrToStructure<LIST_ENTRY>(pInLoadOrderModuleList);

        // Loop entries
        var flink = le.Flink;
        var hModule = IntPtr.Zero;
        var dte = Marshal.PtrToStructure<LDR_DATA_TABLE_ENTRY>(flink);
        
        while (dte.InLoadOrderLinks.Flink != le.Blink)
        {
            // Match module name
            var moduleName = dte.BaseDllName.Buffer.ToString();
            
            if (!string.IsNullOrWhiteSpace(moduleName) && moduleName.Equals(dllName, StringComparison.OrdinalIgnoreCase))
            {
                hModule = dte.DllBase;
                break;
            }

            // Move Ptr
            flink = dte.InLoadOrderLinks.Flink;
            dte = Marshal.PtrToStructure<LDR_DATA_TABLE_ENTRY>(flink);
        }

        return hModule;
    }
    
    /// <summary>
    /// Resolve host DLL for API Set DLL.
    /// </summary>
    /// <author>Ruben Boonen (@FuzzySec), The Wover (@TheRealWover)</author>
    /// <returns>Dictionary, a combination of Key:APISetDLL and Val:HostDLL.</returns>
    public static Dictionary<string, string> GetApiSetMapping()
    {
        var apiSetMapOffset = IntPtr.Size == 4 ? (uint)0x38 : 0x68;
        var apiSetDict = new Dictionary<string, string>();

        var peb = GetPebAddress();

        var pApiSetNamespace = Marshal.ReadIntPtr((IntPtr)((ulong)peb + apiSetMapOffset));
        var apiSetNamespace = Marshal.PtrToStructure<ApiSetNamespace>(pApiSetNamespace);
            
        for (var i = 0; i < apiSetNamespace.Count; i++)
        {
            var setEntry = new ApiSetNamespaceEntry();

            var pSetEntry = (IntPtr)((ulong)pApiSetNamespace + (ulong)apiSetNamespace.EntryOffset + (ulong)(i * Marshal.SizeOf(setEntry)));
            setEntry = Marshal.PtrToStructure<ApiSetNamespaceEntry>(pSetEntry);

            var apiSetEntryName = Marshal.PtrToStringUni((IntPtr)((ulong)pApiSetNamespace + (ulong)setEntry.NameOffset), setEntry.NameLength / 2);
            var apiSetEntryKey = apiSetEntryName.Substring(0, apiSetEntryName.Length - 2) + ".dll" ; // Remove the patch number and add .dll

            var valueEntry = new ApiSetValueEntry();
            var pSetValue = IntPtr.Zero;

            switch (setEntry.ValueLength)
            {
                case 1:
                    pSetValue = (IntPtr)((ulong)pApiSetNamespace + (ulong)setEntry.ValueOffset);
                    break;
                    
                case > 1:
                {
                    for (var j = 0; j < setEntry.ValueLength; j++)
                    {
                        var host = (IntPtr)((ulong)pApiSetNamespace + (ulong)setEntry.ValueOffset + (ulong)Marshal.SizeOf(valueEntry) * (ulong)j);
                        
                        if (Marshal.PtrToStringUni(host) != apiSetEntryName)
                            pSetValue = (IntPtr)((ulong)pApiSetNamespace + (ulong)setEntry.ValueOffset + (ulong)Marshal.SizeOf(valueEntry) * (ulong)j);
                    }
                        
                    if (pSetValue == IntPtr.Zero)
                        pSetValue = (IntPtr)((ulong)pApiSetNamespace + (ulong)setEntry.ValueOffset);
                        
                    break;
                }
            }

            valueEntry = Marshal.PtrToStructure<ApiSetValueEntry>(pSetValue);
                
            var apiSetValue = string.Empty;
            if (valueEntry.ValueCount != 0)
            {
                var pValue = (IntPtr)((ulong)pApiSetNamespace + (ulong)valueEntry.ValueOffset);
                apiSetValue = Marshal.PtrToStringUni(pValue, valueEntry.ValueCount / 2);
            }

            apiSetDict.Add(apiSetEntryKey, apiSetValue);
        }

        return apiSetDict;
    }
    
    /// <summary>
    /// Resolves LdrLoadDll and uses that function to load a DLL from disk.
    /// </summary>
    /// <author>Ruben Boonen (@FuzzySec)</author>
    /// <param name="dllPath">The path to the DLL on disk. Uses the LoadLibrary convention.</param>
    /// <returns>IntPtr base address of the loaded module or IntPtr.Zero if the module was not loaded successfully.</returns>
    public static unsafe IntPtr LoadModuleFromDisk(string dllPath)
    {
        var uModuleName = new UNICODE_STRING();
        Native.RtlInitUnicodeString(&uModuleName, dllPath);

        HANDLE hModule;
        Native.LdrLoadDll(&uModuleName, &hModule);

        return hModule;
    }
    
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate IntPtr ReadGs();
    
    [StructLayout(LayoutKind.Sequential)]
    private struct LIST_ENTRY
    {
        public IntPtr Flink;
        public IntPtr Blink;
    }
    
    [StructLayout(LayoutKind.Sequential)]
    private struct LDR_DATA_TABLE_ENTRY
    {
        public LIST_ENTRY InLoadOrderLinks;
        public LIST_ENTRY InMemoryOrderLinks;
        public LIST_ENTRY InInitializationOrderLinks;
        public IntPtr DllBase;
        public IntPtr EntryPoint;
        public uint SizeOfImage;
        public UNICODE_STRING FullDllName;
        public UNICODE_STRING BaseDllName;
    }
    
    [StructLayout(LayoutKind.Explicit)]
    private struct ApiSetNamespace
    {
        [FieldOffset(0x0C)]
        public int Count;

        [FieldOffset(0x10)]
        public int EntryOffset;
    }
    
    [StructLayout(LayoutKind.Explicit)]
    private struct ApiSetNamespaceEntry
    {
        [FieldOffset(0x04)]
        public int NameOffset;

        [FieldOffset(0x08)]
        public int NameLength;

        [FieldOffset(0x10)]
        public int ValueOffset;

        [FieldOffset(0x14)]
        public int ValueLength;
    }
    
    [StructLayout(LayoutKind.Explicit)]
    private struct ApiSetValueEntry
    {
        [FieldOffset(0x00)]
        public int Flags;

        [FieldOffset(0x04)]
        public int NameOffset;

        [FieldOffset(0x08)]
        public int NameCount;

        [FieldOffset(0x0C)]
        public int ValueOffset;

        [FieldOffset(0x10)]
        public int ValueCount;
    }
}