using System.Diagnostics;

namespace CsWhispers;

[DebuggerDisplay("{Value}")]
public readonly unsafe struct PWSTR : IEquatable<PWSTR>
{
    public readonly char* Value;

    public PWSTR(char* value) => Value = value;

    public static implicit operator char*(PWSTR value) => value.Value;

    public static implicit operator PWSTR(char* value) => new(value);

    public static bool operator ==(PWSTR left, PWSTR right) => left.Value == right.Value;

    public static bool operator !=(PWSTR left, PWSTR right) => !(left == right);

    public bool Equals(PWSTR other) => Value == other.Value;

    public override bool Equals(object obj) => obj is PWSTR other && Equals(other);

    public override int GetHashCode() => (int)Value;

    public override string ToString() => new PCWSTR(Value).ToString();

    public static implicit operator PCWSTR(PWSTR value) => new(value.Value);

    public int Length => new PCWSTR(Value).Length;
}