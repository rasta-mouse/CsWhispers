using System.Runtime.InteropServices;

namespace CsWhispers;

public struct IO_STATUS_BLOCK
{
    public AnonymousUnion Union;
    public nuint Information;

    [StructLayout(LayoutKind.Explicit)]
    public unsafe struct AnonymousUnion
    {
        [FieldOffset(0)]
        public NTSTATUS Status;

        [FieldOffset(0)]
        public void* Pointer;
    }
}