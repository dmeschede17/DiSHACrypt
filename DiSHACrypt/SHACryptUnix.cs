using System.Collections.Immutable;

namespace DiSHACrypt;

/// <summary>
/// Base class for default Unix variant of 'Unix crypt using SHA-256 and SHA-512'.
/// </summary>
public abstract class SHACryptUnix(char digestType, ImmutableArray<int> permutations) : SHACrypt(OptionsUnix, digestType, permutations)
{
    public const string SaltChars = "abcedefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./";

    public static SHACryptOptions OptionsUnix { get; } = new() 
    {
        SaltChars = SaltChars,
        SaltMinLength = 0,
        SaltMaxLength = 16,
        RoundsMultiplier = 1,
        RoundsMin = 1000,
        RoundsMax = 999999999
    };

    protected override string ToDigestString(string salt, int? rounds, ReadOnlySpan<byte> digest)
    {
        string digestStr = Base64CryptEncoder.Encode(digest);
        return $"${DigestType}${(rounds != null ? $"rounds={rounds.Value}$" : "")}{salt}${digestStr}";
    }
}
