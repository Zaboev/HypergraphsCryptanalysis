using System;

namespace Irbis.PhDThesis.Math.Cryptanalysis;

/// <summary>
/// "Взломанный" дешифратор:
/// P = M^{-1} * (C XOR C0)
///
/// Где умножение делается на уровне вершинных блоков:
/// если Minv[i][j] = 1 → XOR'им блок j в блок i.
/// </summary>
public sealed class HackedDecryptor
{
    private readonly bool[][] _Minv;
    private readonly byte[] _c0;
    private readonly int _n;
    private readonly int _smallBlockSize;
    private readonly int _blockSize;

    public HackedDecryptor(VertexMatrixRecovery.RecoveryResult rec)
    {
        _Minv = rec.Minv;
        _c0 = rec.C0;
        _n = rec.VerticesCount;
        _smallBlockSize = rec.SmallBlockSizeBytes;
        _blockSize = rec.BlockSizeBytes;
    }

    public byte[] Decrypt(byte[] ciphertext)
    {
        if (ciphertext == null) throw new ArgumentNullException(nameof(ciphertext));
        if (ciphertext.Length != _blockSize) throw new ArgumentException("Ciphertext length mismatch.");

        // C' = C XOR C0
        var cPrime = (byte[])ciphertext.Clone();
        for (int i = 0; i < _blockSize; i++)
            cPrime[i] ^= _c0[i];

        var plaintext = new byte[_blockSize];

        // For each output vertex i:
        for (int i = 0; i < _n; i++)
        {
            var pi = new Span<byte>(plaintext, i * _smallBlockSize, _smallBlockSize);

            for (int j = 0; j < _n; j++)
            {
                if (!_Minv[i][j]) continue;

                var cj = new ReadOnlySpan<byte>(cPrime, j * _smallBlockSize, _smallBlockSize);
                ByteBlockUtils.XorInto(pi, cj);
            }
        }

        return plaintext;
    }
}