using System.Diagnostics;

namespace CsWhispers;

[DebuggerDisplay("{Value}")]
public readonly struct NTSTATUS : IEquatable<NTSTATUS>
{
    public readonly int Value;

    public NTSTATUS(int value) => Value = value;

    public static implicit operator int(NTSTATUS value) => value.Value;

    public static explicit operator NTSTATUS(int value) => new(value);

    public static bool operator ==(NTSTATUS left, NTSTATUS right) => left.Value == right.Value;

    public static bool operator !=(NTSTATUS left, NTSTATUS right) => !(left == right);

    public bool Equals(NTSTATUS other) => Value == other.Value;

    public override bool Equals(object obj) => obj is NTSTATUS other && Equals(other);

    public override int GetHashCode() => Value.GetHashCode();

    public override string ToString() => $"0x{Value:x}";

    public static implicit operator uint(NTSTATUS value) => (uint)value.Value;

    public static explicit operator NTSTATUS(uint value) => new((int)value);

    public Severity SeverityCode => (Severity)(((uint)Value & 0xc0000000) >> 30);

    public enum Severity
    {
        Success,
        Informational,
        Warning,
        Error,
    }
}