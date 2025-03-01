using System.Diagnostics;
using System.Runtime.CompilerServices;

namespace DiSHACrypt;

/// <summary>
/// Encoder for base-64 format used in 'Unix crypt with SHA-256 and SHA-512'.
/// </summary>
public class Base64CryptEncoder
{
    // Unix crypt with SHA-256 and SHA-512 uses the following encoding:
    //       
    //             111111111122222222223333333333444444444455555555556666
    //   0123456789012345678901234567890123456789012345678901234567890123
    //   ----------------------------------------------------------------
    //   ./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz
    //
    //   Each group of three bytes from the digest produces four characters as output:
    //
    //     1. character: the six low bits of the first byte
    //     2. character: the two high bits of the first byte and the four low bytes from the second byte
    //     3. character: the four high bits from the second byte and the two low bits from the third byte
    //     4. character: the six high bits from the third byte

    const string Base64Chars = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    public static int GetEncodedLength(int bytesLength)
    {
        int bytesLengthDiv3 = bytesLength / 3;
        int remainingBytes = bytesLength - bytesLengthDiv3 * 3;
        int encodedLength = bytesLengthDiv3 * 4;
        if (remainingBytes == 1)
        {
            encodedLength += 2;
        }
        else if (remainingBytes == 2)
        {
            encodedLength += 3;
        }
        else
        {
            Debug.Assert(remainingBytes == 0);
        }
        return encodedLength;
    }

    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    public static string Encode(ReadOnlySpan<byte> bytes)
    {
        int encodedLength = GetEncodedLength(bytes.Length);
        char[] base64Chars = new char[encodedLength];
        Encode(bytes, base64Chars);
        return new(base64Chars);
    }

    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    static void Encode(ReadOnlySpan<byte> bytes, Span<char> base64Chars)
    {
        int i = 0;
        int j = 0;

        while (i + 2 < bytes.Length)
        {
            byte byte0 = bytes[i];
            byte byte1 = bytes[i + 1];
            byte byte2 = bytes[i + 2];

            base64Chars[j] = Base64Chars[byte0 & 63];
            base64Chars[j + 1] = Base64Chars[((byte0 >> 6) | (byte1 << 2)) & 63];
            base64Chars[j + 2] = Base64Chars[((byte1 >> 4) | (byte2 << 4)) & 63];
            base64Chars[j + 3] = Base64Chars[byte2 >> 2];

            i += 3;
            j += 4;
        }

        if (i + 1 < bytes.Length)
        {
            byte byte0 = bytes[i];
            byte byte1 = bytes[i + 1];

            base64Chars[j] = Base64Chars[byte0 & 63];
            base64Chars[j + 1] = Base64Chars[((byte0 >> 6) | (byte1 << 2)) & 63];
            base64Chars[j + 2] = Base64Chars[byte1 >> 4];

            i += 2;
            j += 3;
        }
        else if (i < bytes.Length)
        {
            byte byte0 = bytes[i];

            base64Chars[j] = Base64Chars[byte0 & 63];
            base64Chars[j + 1] = Base64Chars[byte0 >> 6];

            i += 1;
            j += 2;
        }

        Debug.Assert(i == bytes.Length);
    }
}
