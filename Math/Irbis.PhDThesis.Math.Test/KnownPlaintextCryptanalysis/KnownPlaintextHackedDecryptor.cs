using System;

namespace Irbis.PhDThesis.Math.Cryptanalysis.KnownPlaintext;

/// <summary>
/// Дешифратор, восстановленный из known-plaintext модели:
/// P = M^{-1} * (C XOR const).
///
/// const = c в модели C = M*P XOR c.
/// </summary>
public sealed class KnownPlaintextHackedDecryptor
{
    private readonly bool[][] _Minv;
    private readonly byte[] _c;
    private readonly int _n;
    private readonly int _s;

    public KnownPlaintextHackedDecryptor(KnownPlaintextRecoverer.RecoveredModel model)
    {
        _Minv = model.Minv ?? throw new ArgumentNullException(nameof(model.Minv));
        _c = model.C ?? throw new ArgumentNullException(nameof(model.C));
        _n = model.VerticesCount;
        _s = model.SmallBlockSizeBytes;
    }

    public byte[] Decrypt(byte[] ciphertext)
    {
        if (ciphertext == null) throw new ArgumentNullException(nameof(ciphertext));
        if (ciphertext.Length != _n * _s) throw new ArgumentException("Ciphertext size mismatch.");

        // C' = C XOR c
        var cPrime = ByteXor.Xor(ciphertext, _c);

        // P = Minv * C' (на уровне вершинных блоков)
        return KnownPlaintextRecoverer.ApplyMatrixToVertexBlocks(_Minv, cPrime, _n, _s);
    }
}