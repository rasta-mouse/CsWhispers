namespace CsWhispers;

public unsafe struct MEMORY_BASIC_INFORMATION
{
    void* BaseAddress;
    void* AllocationBase;
    uint AllocationProtect;
    ushort PartitionId;
    nuint RegionSize;
    uint State;
    uint Protect;
    uint Type;
}