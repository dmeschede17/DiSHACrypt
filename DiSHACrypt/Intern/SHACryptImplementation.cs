using System.Collections.Immutable;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace DiSHACrypt.Intern;

internal static class SHACryptImplementation
{
    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    static byte[] ProduceSequence(ReadOnlySpan<byte> source, int length)
    {
        if (length <= 0)
        {
            return []; // ### RETURN ###
        }

        byte[] result = new byte[length];
        Span<byte> resultSpan = result;

        int i = 0;

        for (; i + source.Length < length; i += source.Length)
        {
            source.CopyTo(resultSpan.Slice(i));
        }

        source[..(length - i)].CopyTo(resultSpan[i..]);

        return result; // ### RETURN ###
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    static void AppendToBuffer(ref int bufferLength, Span<byte> buffer, ReadOnlySpan<byte> input)
    {
        input.CopyTo(buffer[bufferLength..]);
        bufferLength += input.Length;
    }

    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    internal static byte[] Crypt(byte[] key, byte[] salt, int rounds, HashAlgorithm hashAlgorithm, ImmutableArray<int> permutations)
    {
        key ??= [];
        salt ??= [];

        ArgumentNullException.ThrowIfNull(hashAlgorithm);
        ArgumentNullException.ThrowIfNull(permutations);

        if (permutations.Length != hashAlgorithm.HashSize / 8)
        {
            throw new ArgumentException("Invalid permutations length.", nameof(permutations));
        }

        // *** Digest B ***

        // 4. Start digest B
        // 5. Add the password to digest B
        // 6. Add the salt string to digest B
        // 7. Add the password again to digest B
        // 8. Finish digest B

        hashAlgorithm.TransformBlock(key);
        hashAlgorithm.TransformBlock(salt);
        hashAlgorithm.TransformBlock(key);

        byte[] digestB = hashAlgorithm.TransformFinalBlockAndGetHash();

        // *** Digest A ***

        // 1. Start digest A
        // 2. The password string is added to digest A
        // 3. The salt string is added to digest A

        hashAlgorithm.TransformBlock(key);
        hashAlgorithm.TransformBlock(salt);

        {
            // 9.  For each block of 32 or 64 bytes in the password string add digest B to digest A
            // 10. For the remaining N bytes of the password string add the first N bytes of digest B to digest A

            int i = 0;

            for (; i + digestB.Length < key.Length; i += digestB.Length)
            {
                hashAlgorithm.TransformBlock(digestB);
            }

            hashAlgorithm.TransformBlock(digestB, 0, key.Length - i);
        }

        // 11. For each bit of the binary representation of the length of the password string up to and including the highest 1 - digit,
        //     starting from to lowest bit position (numeric value 1):
        //       - for a 1-digit add digest B to digest A
        //       - for a 0-digit add the password string
        // 12. Finish digest A

        {
            int l = key.Length;
            for (int i = 0; l != 0; i++)
            {
                int bit = 1 << i;
                hashAlgorithm.TransformBlock((l & bit) != 0 ? digestB : key);
                l &= ~bit;
            }
        }

        byte[] digestA = hashAlgorithm.TransformFinalBlockAndGetHash();

        // *** Digest DP ***

        // 13. Start digest DP
        // 14. For every byte in the password add the password to digest DP
        // 15. Finish digest DP

        for (int i = 0; i < key.Length; i++)
        {
            hashAlgorithm.TransformBlock(key);
        }

        byte[] digestDP = hashAlgorithm.TransformFinalBlockAndGetHash();

        // *** Sequence P ***

        // 16. Produce byte sequence P of the same length as the password where
        //     - for each block of 32 or 64 bytes of length of the password string the entire digest DP is used
        //     - for the remaining N (up to  31 or 63) bytes use the first N bytes of digest DP

        byte[] P = ProduceSequence(digestDP, key.Length);

        // *** Digest DS ***

        // 17. Start digest DS
        // 18. Repeat the following 16 + A[0] times, where A[0] represents the first byte in digest A interpreted as an 8-bit unsigned value:
        //     - add the salt to digest DS
        // 19. Finish digest DS

        {
            int i = 16 + digestA[0];

            do
            {
                hashAlgorithm.TransformBlock(salt);
            }
            while (--i > 0);
        }

        byte[] digestDS = hashAlgorithm.TransformFinalBlockAndGetHash();

        // *** Sequence S ***

        // 20. Produce byte sequence S of the same length as the salt string where
        //       - for each block of 32 or 64 bytes of length of the salt string the entire digest DS is used
        //       - for the remaining N (up to  31 or 63) bytes use the first N bytes of digest DS

        byte[] S = ProduceSequence(digestDS, salt.Length);

        // *** Digest C ***

        // 21. Repeat a loop according to the specified number of rounds N.
        //     Each round is numbered, starting with 0 and up to N-1.
        //     The loop uses a digest as input. In the first round it is the digest produced in step 12.
        //     In the latter steps it is the digest produced in step 21. h) of the previous round.
        //     The following text uses the notation "digest A/C" to describe this behavior.
        //       a) start digest C
        //       b) for odd round numbers add the byte sequense P to digest C
        //       c) for even round numbers add digest A / C
        //       d) for all round numbers not divisible by 3 add the byte sequence S
        //       e) for all round numbers not divisible by 7 add the byte sequence P
        //       f) for odd round numbers add digest A / C
        //       g) for even round numbers add the byte sequence P
        //       h) finish digest C

        byte[] digestC = digestA;

        int digestCBufferLength = 0;
        Span<byte> digestCBuffer = new byte[P.Length + digestC.Length + S.Length + P.Length];

        for (int r = 0; r < rounds; r++)
        {
            digestCBufferLength = 0;

            if ((r & 1) != 0) AppendToBuffer(ref digestCBufferLength, digestCBuffer, P);
            else AppendToBuffer(ref digestCBufferLength, digestCBuffer, digestC);
            if (r % 3 != 0) AppendToBuffer(ref digestCBufferLength, digestCBuffer, S);
            if (r % 7 != 0) AppendToBuffer(ref digestCBufferLength, digestCBuffer, P);
            if ((r & 1) != 0) AppendToBuffer(ref digestCBufferLength, digestCBuffer, digestC);
            else AppendToBuffer(ref digestCBufferLength, digestCBuffer, P);

            bool computeHashOk = hashAlgorithm.TryComputeHash(digestCBuffer.Slice(0, digestCBufferLength), digestC, out int bytesWritten);

            Debug.Assert(computeHashOk);
            Debug.Assert(bytesWritten == digestC.Length);
        }

        // *** Digest ***

        byte[] digest = new byte[digestC.Length];

        Debug.Assert(permutations.Length == digest.Length);

        for (int i = 0; i < digest.Length; i++)
        {
            digest[i] = digestC[permutations[i]];
        }

        return digest; // ### RETURN ###
    }
}
