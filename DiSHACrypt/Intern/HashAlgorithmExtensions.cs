using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace DiSHACrypt.Intern;

internal static class HashAlgorithmExtensions
{
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static void TransformBlock(this HashAlgorithm hashAlgorithm, byte[] input)
    {
        hashAlgorithm.TransformBlock(input, 0, input.Length, null, 0);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static void TransformBlock(this HashAlgorithm hashAlgorithm, byte[] input, int inputOffset, int inputLength)
    {
        hashAlgorithm.TransformBlock(input, inputOffset, inputLength, null, 0);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static byte[] TransformFinalBlockAndGetHash(this HashAlgorithm hashAlgorithm)
    {
        hashAlgorithm.TransformFinalBlock([], 0, 0);
        byte[] hash = hashAlgorithm.Hash!;
        Debug.Assert(hash != null);
        return hash;
    }
}
