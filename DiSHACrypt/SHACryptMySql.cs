using System.Collections.Immutable;

namespace DiSHACrypt;

/// <summary>
/// Base class for MySQL variant of 'Unix crypt using SHA-256 and SHA-512'.
/// 
/// A major difference is that the MySQL variant uses a fixed salt length of 20, which is larger than the maximum of 16 used in Unix crypt.
/// </summary>
public abstract class SHACryptMySql(char digestType, ImmutableArray<int> permutations) : SHACrypt(OptionsMySql, digestType, permutations)
{
    // MySQL authentication_string format for caching_sha2_password:
    //
    //   DELIMITER[digest_type]DELIMITER[iterations]DELIMITER[salt][digest]
    //
    // Where:
    //
    //   - DELIMITER = '$'
    //   - digest_type = 'A' (SHA256)
    //   - iterations = 3 hexadecimal digits (Number of iterations = [iterations] * 1000)
    //   - salt = Random string of length 20
    //   - digest = SHA-256 digest of the password (length 43)

    public const string SaltChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#%&()*+,-./:;<=>?@[]^_{|}~";

    const int RoundsMultiplier = 1000;

    public static SHACryptOptions OptionsMySql { get; } = new() 
    {
        SaltChars = SaltChars,
        SaltMinLength = 20,
        SaltMaxLength = 20,
        RoundsMultiplier = RoundsMultiplier,
        RoundsMin = 5 * RoundsMultiplier,
        RoundsMax = 0xFFF * RoundsMultiplier
    };

    protected override string ToDigestString(string salt, int? rounds, ReadOnlySpan<byte> digest)
    {
        string digestStr = Base64CryptEncoder.Encode(digest);
        return $"${DigestType}${(rounds ?? DefaultRounds) / RoundsMultiplier:X3}${salt}{digestStr}";
    }
}
