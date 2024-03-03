namespace CsWhispers;

public unsafe struct MEMORY_BASIC_INFORMATION
{
    public void* BaseAddress;
    public void* AllocationBase;
    public uint AllocationProtect;
    public ushort PartitionId;
    public nuint RegionSize;
    public uint State;
    public uint Protect;
    public uint Type;
}