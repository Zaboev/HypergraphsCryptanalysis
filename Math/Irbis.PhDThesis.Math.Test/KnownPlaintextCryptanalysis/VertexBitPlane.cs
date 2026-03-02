using System;

namespace Irbis.PhDThesis.Math.Cryptanalysis.KnownPlaintext;

/// <summary>
/// Извлекает "битовую плоскость" из блочного представления:
/// у нас n вершин, каждая вершина занимает s байт.
/// Берём один фиксированный bitInVertexBlock (0..8*s-1) и
/// строим вектор длины n из соответствующих бит (по одному на вершину).
///
/// Важно: битовая плоскость нужна, чтобы свести векторные уравнения (по byte-блокам)
/// к скалярным уравнениям над GF(2), и восстановить матрицу M (n×n).
/// </summary>
public static class VertexBitPlane
{
    /// <summary>
    /// bitInVertexBlock: 0..(8*s-1).
    /// Нумерация бит в байте: MSB-first (как в твоих листингах): 7-(pos%8).
    /// </summary>
    public static bool[] ExtractVertexBits(byte[] block, int n, int s, int bitInVertexBlock)
    {
        if (block == null) throw new ArgumentNullException(nameof(block));
        if (n <= 0) throw new ArgumentOutOfRangeException(nameof(n));
        if (s <= 0) throw new ArgumentOutOfRangeException(nameof(s));
        if (block.Length != n * s) throw new ArgumentException("Block length mismatch.");
        if (bitInVertexBlock < 0 || bitInVertexBlock >= 8 * s) throw new ArgumentOutOfRangeException(nameof(bitInVertexBlock));

        int byteInVertex = bitInVertexBlock / 8;
        int bitInByte = 7 - (bitInVertexBlock % 8);

        var v = new bool[n];
        for (int i = 0; i < n; i++)
        {
            byte b = block[i * s + byteInVertex];
            v[i] = ((b >> bitInByte) & 1) == 1;
        }

        return v;
    }
}