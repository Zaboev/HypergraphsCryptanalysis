using System;

namespace Irbis.PhDThesis.Math.Cryptanalysis;

/// <summary>
/// Восстановление матрицы преобразования M на уровне вершин.
///
/// Почему именно "уровень вершин", а не битов:
/// - HomogenousHypergraphEncryptor делает XOR блоками _smallBlockSize байт на вершину
///   и нигде не перемешивает байты/биты внутри блока. :contentReference[oaicite:7]{index=7}
/// - значит каждый выходной "вершинный блок" = XOR некоторых входных "вершинных блоков".
/// - коэффициенты 0/1 → матрица M размера n x n.
///
/// Это прямой аналог твоего листинга 1–4, только "единичный вектор" = включена одна вершина (её блок байт).
/// </summary>
public static class VertexMatrixRecovery
{
    public sealed record RecoveryResult(
        bool[][] M,
        bool[][] Minv,
        byte[] C0,
        int VerticesCount,
        int SmallBlockSizeBytes,
        int BlockSizeBytes);

    /// <summary>
    /// Полный пайплайн:
    /// 1) C0 = E(0) (на случай аффинности/режима, хотя для ядра шифра C0 обычно = 0)
    /// 2) Снимаем столбцы M: E(e_col) XOR C0
    /// 3) Инвертируем M
    /// </summary>
    public static RecoveryResult Recover(IEncryptionOracle oracle, int verticesCount, int smallBlockSizeBytes, byte patternByte = 0xA5)
    {
        if (oracle == null) throw new ArgumentNullException(nameof(oracle));
        if (verticesCount <= 0) throw new ArgumentOutOfRangeException(nameof(verticesCount));
        if (smallBlockSizeBytes <= 0) throw new ArgumentOutOfRangeException(nameof(smallBlockSizeBytes));

        int blockSizeBytes = verticesCount * smallBlockSizeBytes;
        if (oracle.BlockSizeBytes != blockSizeBytes)
            throw new ArgumentException($"Oracle block size is {oracle.BlockSizeBytes}, but expected {blockSizeBytes} (= n * smallBlockSizeBytes).");

        // C0 = E(0)
        var zero = new byte[blockSizeBytes];
        var c0 = oracle.Encrypt(zero);

        // pattern for "one active vertex"
        var pattern = new byte[smallBlockSizeBytes];
        ByteBlockUtils.FillPattern(pattern, patternByte);

        // M[row][col]
        var M = new bool[verticesCount][];
        for (int r = 0; r < verticesCount; r++)
            M[r] = new bool[verticesCount];

        // For each column (activate one vertex)
        for (int col = 0; col < verticesCount; col++)
        {
            var p = new byte[blockSizeBytes];
            Array.Copy(pattern, 0, p, col * smallBlockSizeBytes, smallBlockSizeBytes);

            var c = oracle.Encrypt(p);

            // delta = E(e_col) XOR C0
            for (int i = 0; i < blockSizeBytes; i++)
                c[i] ^= c0[i];

            // Read rows: each row-block must be either 0 or == pattern
            for (int row = 0; row < verticesCount; row++)
            {
                var rowBlock = new ReadOnlySpan<byte>(c, row * smallBlockSizeBytes, smallBlockSizeBytes);

                if (ByteBlockUtils.IsAllZero(rowBlock))
                {
                    M[row][col] = false;
                }
                else if (ByteBlockUtils.SequenceEqual(rowBlock, pattern))
                {
                    M[row][col] = true;
                }
                else
                {
                    // Это сигнал, что что-то неожиданное происходит внутри блока (не просто XOR коэффициенты 0/1)
                    // или неверно выбран размер smallBlockSizeBytes / verticesCount.
                    throw new InvalidOperationException(
                        $"Unexpected block value at row={row}, col={col}. " +
                        $"Expected all-zero or exact pattern. Check parameters and mode.");
                }
            }
        }

        var Minv = Gf2GaussJordan.Invert(M);
        return new RecoveryResult(M, Minv, c0, verticesCount, smallBlockSizeBytes, blockSizeBytes);
    }
}