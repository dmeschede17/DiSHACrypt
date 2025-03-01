using System.Security.Cryptography;

namespace DiSHACrypt;

/// <summary>
/// MySQL variant of 'Unix crypt using SHA-256 and SHA-512' using SHA-256 as used for 'caching_sha2_password'.
/// </summary>
public sealed class SHACryptMySqlSHA256() : SHACryptMySql(DigestTypeMySqlSHA256, SHACryptSHA256.PermutationsSHA256)
{
    public const char DigestTypeMySqlSHA256 = 'A';

    protected override HashAlgorithm CreateHashAlgorithm() => SHA256.Create();
}
