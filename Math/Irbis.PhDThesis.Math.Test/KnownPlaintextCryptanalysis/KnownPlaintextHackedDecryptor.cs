using System;

namespace Irbis.PhDThesis.Math.Cryptanalysis.KnownPlaintext;

/// <summary>
/// Дешифратор, восстановленный из known-plaintext модели без константы:
///     C = M*P  =>  P = M^{-1} * C
/// </summary>
public sealed class KnownPlaintextHackedDecryptor
{
    private readonly bool[][] _Minv;
    private readonly int _n;
    private readonly int _s;

    public KnownPlaintextHackedDecryptor(KnownPlaintextRecoverer.RecoveredModel model)
    {
        _Minv = model.Minv ?? throw new ArgumentNullException(nameof(model.Minv));
        _n = model.VerticesCount;
        _s = model.SmallBlockSizeBytes;
    }

    public byte[] Decrypt(byte[] ciphertext)
    {
        if (ciphertext == null) throw new ArgumentNullException(nameof(ciphertext));
        if (ciphertext.Length != _n * _s) throw new ArgumentException("Неверный размер шифртекста.");

        // P = Minv * C (на уровне вершинных блоков)
        return KnownPlaintextRecoverer.ApplyMatrixToVertexBlocks(_Minv, ciphertext, _n, _s);
    }
}