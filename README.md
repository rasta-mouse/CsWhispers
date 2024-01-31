# CsWhispers

Source generator to add D/Invoke and indirect syscall methods to a C# project.

## Quick Start

Add the latest NuGet package to your project and allow unsafe code.

```xml
<Project Sdk="Microsoft.NET.Sdk">

    <PropertyGroup>
        <OutputType>Exe</OutputType>
        <TargetFramework>net481</TargetFramework>
        <ImplicitUsings>enable</ImplicitUsings>
        <Nullable>enable</Nullable>
        <LangVersion>12</LangVersion>
    </PropertyGroup>

    <!-- CsWhispers package -->
    <ItemGroup>
      <PackageReference Include="CsWhispers" Version="0.0.3" />
    </ItemGroup>

    <!-- Allow unsafe code -->
    <PropertyGroup Condition=" '$(Configuration)' == 'Debug' ">
      <AllowUnsafeBlocks>true</AllowUnsafeBlocks>
    </PropertyGroup>

    <PropertyGroup Condition=" '$(Configuration)' == 'Release' ">
      <AllowUnsafeBlocks>true</AllowUnsafeBlocks>
    </PropertyGroup>

</Project>
```

Create a file in your project called `CsWhispers.txt` and set its build action properties to `AdditionalFiles`.

```xml
<ItemGroup>
  <None Remove="CsWhispers.txt" />
  <AdditionalFiles Include="CsWhispers.txt" />
</ItemGroup>
```

Add each NT API and any supporting structs/enums that you want to be included in your project. Each must be on its own line, for example:

```text
NtOpenProcess

HANDLE
NTSTATUS
CLIENT_ID
UNICODE_STRING
OBJECT_ATTRIBUTES

PWSTR
PCWSTR
```

**See the project Wiki for a full list of supported APIs.**

Global namespaces are automatically added to allow for clean code.

```c#
public static unsafe void Main()
{
    // use self as example
    using var self = Process.GetCurrentProcess();
        
    HANDLE hProcess;
    OBJECT_ATTRIBUTES oa;
    CLIENT_ID cid = new()
    {
        UniqueProcess = new HANDLE((IntPtr)self.Id)
    };

    var status = NtOpenProcess(
        &hProcess,
        PROCESS_ALL_ACCESS,
        &oa,
        &cid);

    Console.WriteLine("Status: {0}", status.SeverityCode);
    Console.WriteLine("HANDLE: 0x{0:X}", hProcess.Value.ToInt64());
}
```

## D/Invoke

CsWhispers includes a minimalised version of D/Invoke, so you may also call `Generic.GetLibraryAddress`, `Generic.DynamicFunctionInvoke`, etc.

## Extending

All of the generated code goes into a partial `CsWhispers.Syscalls` class, which you can extend to add your own APIs. For example, create `MyAPIs.cs` and add:

```c#
namespace CsWhispers;

public static partial class Syscalls
{
    public static NTSTATUS NtCreateThreadEx()
    {
        // whatever
        return new NTSTATUS(0);
    }
}
```

This can then be called in your main code without having to add any additional using statements.

```c#
namespace ConsoleApp1;

internal static class Program
{
    public static void Main()
    {
        var status = NtCreateThreadEx();
    }
}
```

## TODO

- Add 32-bit support.
- Randomise API hashes on each build.
- Add additional configuration options to choose between direct and indirect syscalls.
- Implicitly add structs/enums for APIs without having to declare them in `CsWhispers.txt`.

## Acknowledgements

This project was inspired by the previous versions of SysWhipsers and SharpWhispers in particular.  So hat's off to [@Jackson_T](https://twitter.com/Jackson_T), [@KlezVirus](https://twitter.com/KlezVirus), [@d_glenx](https://twitter.com/d_glenx), and everyone else that has contribured code and/or ideas.