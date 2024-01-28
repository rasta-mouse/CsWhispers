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
      <PackageReference Include="CsWhispers" Version="0.0.2" />
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

See the project Wiki for a full list of supported APIs.

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
