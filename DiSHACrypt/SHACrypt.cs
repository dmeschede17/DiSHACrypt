using DiSHACrypt.Intern;
using System.Collections.Immutable;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

namespace DiSHACrypt;

/// <summary>
/// Base class for algorithm 'Unix crypt using SHA-256 and SHA-512'.
/// </summary>
public abstract class SHACrypt(SHACryptOptions options, char digestType, ImmutableArray<int> permutations)
{
    public const int DefaultRounds = 5000;

    public SHACryptOptions Options { get; } = options;
    public char DigestType { get; } = digestType;

    protected ImmutableArray<int> Permutations { get; } = permutations;

    protected abstract HashAlgorithm CreateHashAlgorithm();
    protected abstract string ToDigestString(string salt, int? rounds, ReadOnlySpan<byte> digest);

    /// <summary>
    /// Generates a random salt string (using the SaltChars from the Options).
    /// If saltLength is not provided, SaltMaxLength from the Options is used as salt length.
    /// If saltLength is less than the SaltMinLength from the Options, an exception is thrown.
    /// </summary>
    public string GenerateSalt(int? saltLength = null)
    {
        if (saltLength == null)
        {
            saltLength = Options.SaltMaxLength;
        }

        if (saltLength.Value < Options.SaltMinLength)
        {
            throw new ArgumentOutOfRangeException(nameof(saltLength), "The salt length is too short.");
        }

        if (saltLength.Value > Options.SaltMaxLength)
        {
            saltLength = Options.SaltMaxLength;
        }

        return new(RandomNumberGenerator.GetItems<char>(Options.SaltChars, saltLength.Value));
    }

    /// <summary>
    /// Checks the salt string and adjusts it according to the Options.
    /// </summary>
    public string CheckAndAdjustSalt(string? salt)
    {
        if (salt == null)
        {
            return GenerateSalt();
        }
        else if (salt.Length > Options.SaltMaxLength)
        {
            return salt[..Options.SaltMaxLength];
        }
        else if (salt.Length < Options.SaltMinLength)
        {
            throw new ArgumentException("The salt length is too short.", nameof(salt));
        }
        else
        {
            return salt;
        }
    }

    /// <summary>
    /// Adjusts the rounds according to the Options.
    /// </summary>
    public int? AdjustRounds(int? rounds)
    {
        if (rounds == null)
        {
            return null;
        }

        int roundsMultipler = Options.RoundsMultiplier;

        return Math.Min(Math.Max((rounds .Value + roundsMultipler - 1) / roundsMultipler * roundsMultipler, Options.RoundsMin), Options.RoundsMax);
    }

    /// <summary>
    /// Computes the digest string according to the algorithm 'Unix crypt using SHA-256 and SHA-512'.
    /// The parameters salt and rounds are adjusted according to the Options.
    /// </summary>
    public string Crypt(string password, string? salt = null, int? rounds = null)
    {
        salt = CheckAndAdjustSalt(salt);
        rounds = AdjustRounds(rounds);

        int roundsOrDefault = rounds ?? DefaultRounds;

        Debug.Assert(salt != null);
        Debug.Assert(salt.Length >= Options.SaltMinLength);
        Debug.Assert(salt.Length <= Options.SaltMaxLength);

        Debug.Assert(roundsOrDefault % Options.RoundsMultiplier == 0);
        Debug.Assert(roundsOrDefault >= Options.RoundsMin);
        Debug.Assert(roundsOrDefault <= Options.RoundsMax);

        byte[] passwordBytes = Encoding.UTF8.GetBytes(password ?? string.Empty);
        byte[] saltBytes = Encoding.ASCII.GetBytes(salt);

        using HashAlgorithm hashAlgorithm = CreateHashAlgorithm();

        byte[] digestBytes = SHACryptImplementation.Crypt(passwordBytes, saltBytes, roundsOrDefault, hashAlgorithm, Permutations);

        return ToDigestString(salt, rounds, digestBytes);
    }

    /// <summary>
    /// Computes the digest according to the algorithm 'Unix crypt using SHA-256 and SHA-512'.
    /// The provided parameters are used directly without any adjustments (i.e., Options are ignored).
    /// </summary>
    public byte[] Crypt(byte[] key, byte[] salt, int rounds)
    {
        using HashAlgorithm hashAlgorithm = CreateHashAlgorithm();

        return SHACryptImplementation.Crypt(key, salt, rounds, hashAlgorithm, Permutations);
    }
}
