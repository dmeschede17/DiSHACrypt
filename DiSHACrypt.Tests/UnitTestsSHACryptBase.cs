using System.Text;

namespace DiSHACrypt.Tests;

public class UnitTestsSHACryptBase<TSHACrypt> where TSHACrypt : SHACrypt, new ()
{
    protected static void CryptReturnsExpectedDigest(string expectedDigest, string keyBase64, string saltStr, int? rounds)
    {
        TSHACrypt crypt = new();
        byte[] key = Convert.FromBase64String(keyBase64);
        byte[] salt = Encoding.ASCII.GetBytes(saltStr);
        byte[] digestBytes = crypt.Crypt(key, salt, rounds ?? SHACrypt.DefaultRounds);
        string digest = Base64CryptEncoder.Encode(digestBytes);
        Assert.Equal(expectedDigest, digest);
    }

    protected static void CryptReturnsExpectedDigestString(string expectedDigestString, string password, string? salt, int? rounds)
    {
        TSHACrypt crypt = new();
        string digestString = crypt.Crypt(password, salt, rounds);
        Assert.Equal(expectedDigestString, digestString);
    }
}
