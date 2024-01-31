using System.Runtime.InteropServices;

namespace CsWhispers;

[UnmanagedFunctionPointer(CallingConvention.StdCall)]
public unsafe delegate NTSTATUS USER_THREAD_START_ROUTINE(void* threadParameter);