namespace DiSHACrypt;

/// <summary>
/// Options defining the behavior of the SHA crypt algorithm.
/// </summary>
public record class SHACryptOptions
{
    public required string SaltChars { get; init; }

    public required int SaltMinLength { get; init; }
    public required int SaltMaxLength { get; init; }

    public required int RoundsMultiplier { get; init; }

    public required int RoundsMin { get; init; }
    public required int RoundsMax { get; init; }
}
