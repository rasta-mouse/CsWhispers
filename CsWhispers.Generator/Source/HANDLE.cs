using System.Diagnostics;

namespace CsWhispers;

[DebuggerDisplay("{Value}")]
public readonly struct HANDLE(IntPtr value) : IEquatable<HANDLE>
{
    public readonly IntPtr Value = value;

    public static HANDLE Null => default;

    public bool IsNull => Value == default;

    public static implicit operator IntPtr(HANDLE value) => value.Value;

    public static explicit operator HANDLE(IntPtr value) => new(value);

    public static bool operator ==(HANDLE left, HANDLE right) => left.Value == right.Value;

    public static bool operator !=(HANDLE left, HANDLE right) => !(left == right);

    public bool Equals(HANDLE other) => Value == other.Value;

    public override bool Equals(object obj) => obj is HANDLE other && Equals(other);

    public override int GetHashCode() => Value.GetHashCode();

    public override string ToString() => $"0x{Value:x}";
}