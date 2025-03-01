using System.Collections.Immutable;
using System.Security.Cryptography;

namespace DiSHACrypt;

/// <summary>
/// SHA-256 implementation of 'Unix crypt using SHA-256 and SHA-512'.
/// </summary>
public sealed class SHACryptSHA256() : SHACryptUnix(DigestTypeSHA256, PermutationsSHA256)
{
    public const char DigestTypeSHA256 = '5';

    internal static ImmutableArray<int> PermutationsSHA256 { get; } =
    [
        20, 10, 0, 11, 1, 21, 2, 22, 12, 23, 13, 3, 14, 4, 24, 5, 25, 15, 26, 16, 6, 17, 7, 27, 8, 28, 18, 29, 19, 9, 30, 31
    ];

    protected override HashAlgorithm CreateHashAlgorithm() => SHA256.Create();
}
