using System;
using System.Collections.Generic;
using Irbis.PhDThesis.Math.Domain;
using Irbis.PhDThesis.Math.Encryption;

namespace Irbis.PhDThesis.Math.Cryptanalysis.KnownPlaintext;

/// <summary>
/// Генератор "перехваченных" пар (P,C) для тестирования known-plaintext атаки.
/// В реальной атаке у тебя вместо этого будут реальные пары, добытые другим способом.
/// </summary>
public static class PairsGenerator
{
    public static List<PlainCipherPair> Generate(
        HomogenousHypergraph key,
        int smallBlockSizeBytes,
        int pairsCount,
        int seed = 123456)
    {
        if (key == null) throw new ArgumentNullException(nameof(key));
        if (smallBlockSizeBytes <= 0) throw new ArgumentOutOfRangeException(nameof(smallBlockSizeBytes));
        if (pairsCount <= 1) throw new ArgumentOutOfRangeException(nameof(pairsCount), "Need at least 2 pairs.");

        var rng = new Random(seed);
        var encryptor = new HomogenousHypergraphEncryptor(key, smallBlockSizeBytes);
        int blockSize = encryptor.BlockSize; // = VerticesCount * smallBlockSizeBytes :contentReference[oaicite:1]{index=1}

        var pairs = new List<PlainCipherPair>(pairsCount);

        for (int i = 0; i < pairsCount; i++)
        {
            var p = new byte[blockSize];
            rng.NextBytes(p);

            byte[]? c = null;
            encryptor.Encrypt(p, ref c);

            pairs.Add(new PlainCipherPair(p, c!));
        }

        return pairs;
    }
}