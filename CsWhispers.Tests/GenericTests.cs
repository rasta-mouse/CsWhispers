namespace CsWhispers.Tests;

public sealed class GenericTests
{
    [Fact]
    public void GetPebAddress()
    {
        var peb = Generic.GetPebAddress();
        Assert.NotEqual(IntPtr.Zero, peb);
    }

    [Fact]
    public void GetLoadedLibraryAddress()
    {
        var hFunction = Generic.GetLibraryAddress(
            "kernel32.dll",
            "OpenProcess");

        Assert.NotEqual(IntPtr.Zero, hFunction);
    }

    [Fact]
    public void GetUnloadedLibraryAddress()
    {
        var hFunction = Generic.GetLibraryAddress(
            "secur32.dll",
            "LsaConnectUntrusted",
            true);
        
        Assert.NotEqual(IntPtr.Zero, hFunction);
    }
}