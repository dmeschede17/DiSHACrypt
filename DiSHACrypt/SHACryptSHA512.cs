using System.Collections.Immutable;
using System.Security.Cryptography;

namespace DiSHACrypt;

/// <summary>
/// SHA-512 implementation of 'Unix crypt using SHA-256 and SHA-512'.
/// </summary>
public sealed class SHACryptSHA512() : SHACryptUnix(DigestTypeSHA512, PermutationsSHA512)
{
    public const char DigestTypeSHA512 = '6';

    internal static ImmutableArray<int> PermutationsSHA512 { get; } =
    [
        42, 21, 0, 1, 43, 22, 23, 2, 44, 45, 24, 3, 4, 46, 25, 26, 5, 47, 48, 27, 6, 7, 49, 28, 29, 8, 50, 51,  30, 9, 10, 52, 31, 
        32, 11, 53, 54, 33, 12, 13, 55, 34, 35, 14, 56, 57, 36, 15, 16, 58, 37, 38, 17, 59, 60, 39, 18, 19, 61, 40, 41, 20, 62, 63
    ];

    protected override HashAlgorithm CreateHashAlgorithm() => SHA512.Create();
}
