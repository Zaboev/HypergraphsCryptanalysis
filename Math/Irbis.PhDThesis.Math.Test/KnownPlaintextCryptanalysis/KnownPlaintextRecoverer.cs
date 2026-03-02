using System;
using System.Collections.Generic;

namespace Irbis.PhDThesis.Math.Cryptanalysis.KnownPlaintext;

/// <summary>
/// Восстановление матрицы M и константы c из known-plaintext пар (P_i, C_i),
/// без доступа к оракулу шифрования.
///
/// Модель (на уровне вершинных блоков):
///   C = M * P XOR c
///
/// Где:
/// - n = число вершин
/// - s = smallBlockSize в БАЙТАХ (как в HomogenousHypergraphEncryptor)
/// - блок = n*s байт
/// - M — бинарная матрица n×n над GF(2), одинаковая для всех битов внутри блока вершины.
/// </summary>
public static class KnownPlaintextRecoverer
{
    public sealed record RecoveredModel(
        bool[][] M,
        bool[][] Minv,
        byte[] C,
        int VerticesCount,
        int SmallBlockSizeBytes);

    /// <summary>
    /// pairs: список пар (P,C) (все должны быть зашифрованы одним ключом/режимом)
    /// n: число вершин
    /// s: smallBlockSize в байтах
    /// </summary>
    public static RecoveredModel Recover(IReadOnlyList<PlainCipherPair> pairs, int n, int s, int maxValidationPairs = 50)
    {
        if (pairs == null) throw new ArgumentNullException(nameof(pairs));
        if (pairs.Count < 2) throw new ArgumentException("Need at least 2 pairs.", nameof(pairs));
        if (n <= 0) throw new ArgumentOutOfRangeException(nameof(n));
        if (s <= 0) throw new ArgumentOutOfRangeException(nameof(s));

        int blockSize = n * s;

        // Проверяем размеры
        for (int i = 0; i < pairs.Count; i++)
        {
            if (pairs[i].Plaintext == null || pairs[i].Ciphertext == null)
                throw new ArgumentException("Null plaintext/ciphertext in pairs.");

            if (pairs[i].Plaintext.Length != blockSize || pairs[i].Ciphertext.Length != blockSize)
                throw new ArgumentException("Pair block size mismatch.");
        }

        // Базовая пара (P0,C0): через неё убираем константу (аффинность)
        byte[] P0 = pairs[0].Plaintext;
        byte[] C0 = pairs[0].Ciphertext;

        // Считаем ΔP_i = P_i XOR P0 и ΔC_i = C_i XOR C0 для i>=1
        int m = pairs.Count - 1;
        var deltaP = new List<byte[]>(m);
        var deltaC = new List<byte[]>(m);

        for (int i = 1; i < pairs.Count; i++)
        {
            deltaP.Add(ByteXor.Xor(pairs[i].Plaintext, P0));
            deltaC.Add(ByteXor.Xor(pairs[i].Ciphertext, C0));
        }

        // Пробуем разные "битовые плоскости" внутри блока вершины (0..8*s-1).
        // На одной плоскости получаем уравнения над GF(2): cVec = M * pVec.
        for (int bitPlane = 0; bitPlane < 8 * s; bitPlane++)
        {
            // pVectors[k] и cVectors[k] — векторы длины n (по одному биту на вершину)
            var pVectors = new bool[m][];
            var cVectors = new bool[m][];

            for (int i = 0; i < m; i++)
            {
                pVectors[i] = VertexBitPlane.ExtractVertexBits(deltaP[i], n, s, bitPlane);
                cVectors[i] = VertexBitPlane.ExtractVertexBits(deltaC[i], n, s, bitPlane);
            }

            // Выбираем n линейно независимых pVectors (иначе PΔ не обратима)
            int[] chosen = IndependentVectorSelector.SelectIndices(pVectors, n, requiredRank: n);
            if (chosen.Length < n)
                continue;

            // Формируем PΔ и CΔ как матрицы из столбцов
            var Pcols = new bool[n][];
            var Ccols = new bool[n][];

            for (int k = 0; k < n; k++)
            {
                Pcols[k] = pVectors[chosen[k]];
                Ccols[k] = cVectors[chosen[k]];
            }

            bool[][] Pmat = Gf2Matrix.FromColumns(Pcols);
            bool[][] Cmat = Gf2Matrix.FromColumns(Ccols);

            bool[][] Pinv;
            try
            {
                Pinv = Gf2Matrix.Invert(Pmat);
            }
            catch
            {
                continue; // не обратима -> недостаточно хорошая выборка
            }

            // M = CΔ * (PΔ)^{-1}
            bool[][] M = Gf2Matrix.Multiply(Cmat, Pinv);

            // Валидация M на части данных (на нескольких битовых плоскостях)
            if (!ValidateCandidateM(M, deltaP, deltaC, n, s, bitPlane, maxValidationPairs))
                continue;

            // Константа c = C0 XOR (M*P0)  (уже на уровне байтовых блоков вершин)
            byte[] cConst = ComputeConstantBytes(M, P0, C0, n, s);

            // Для дешифрования нужен Minv
            bool[][] Minv = Gf2Matrix.Invert(M);

            return new RecoveredModel(M, Minv, cConst, n, s);
        }

        throw new InvalidOperationException(
            "Failed to recover M from known-plaintext pairs. " +
            "Not enough independent data (rank), or pairs are not under same key/mode.");
    }

    private static bool ValidateCandidateM(
        bool[][] M,
        List<byte[]> deltaP,
        List<byte[]> deltaC,
        int n,
        int s,
        int mainBitPlane,
        int maxPairs)
    {
        int tests = global::System.Math.Min(deltaP.Count, maxPairs);

        // Проверим на нескольких плоскостях: основной и ещё пару (без LINQ, без Distinct)
        int p1 = mainBitPlane;
        int p2 = global::System.Math.Min(mainBitPlane + 1, 8 * s - 1);
        int p3 = global::System.Math.Min(mainBitPlane + 7, 8 * s - 1);

        // Собираем уникальные плоскости вручную
        int[] planesTmp = new[] { p1, p2, p3 };
        int[] planes = UniqueInts(planesTmp);

        for (int idx = 0; idx < tests; idx++)
        {
            for (int pi = 0; pi < planes.Length; pi++)
            {
                int plane = planes[pi];

                bool[] pVec = VertexBitPlane.ExtractVertexBits(deltaP[idx], n, s, plane);
                bool[] cVec = VertexBitPlane.ExtractVertexBits(deltaC[idx], n, s, plane);

                bool[] predicted = Gf2Matrix.Multiply(M, pVec);

                if (!EqualBits(predicted, cVec))
                    return false;
            }
        }

        return true;
    }

    private static int[] UniqueInts(int[] a)
    {
        // максимум тут 3 элемента, сделаем просто
        var tmp = new int[3];
        int count = 0;

        for (int i = 0; i < a.Length; i++)
        {
            int v = a[i];
            bool exists = false;
            for (int j = 0; j < count; j++)
                if (tmp[j] == v) { exists = true; break; }
            if (!exists) tmp[count++] = v;
        }

        var r = new int[count];
        for (int i = 0; i < count; i++) r[i] = tmp[i];
        return r;
    }

    private static bool EqualBits(bool[] a, bool[] b)
    {
        if (a.Length != b.Length) return false;
        for (int i = 0; i < a.Length; i++)
            if (a[i] != b[i]) return false;
        return true;
    }

    /// <summary>
    /// c = C0 XOR (M * P0), где M*P0 делается на уровне блоков вершин (s байт).
    /// </summary>
    private static byte[] ComputeConstantBytes(bool[][] M, byte[] P0, byte[] C0, int n, int s)
    {
        byte[] MP0 = ApplyMatrixToVertexBlocks(M, P0, n, s);
        return ByteXor.Xor(C0, MP0);
    }

    /// <summary>
    /// y = M*x на уровне "вершинных блоков":
    /// y_j = XOR_{i: M[j,i]=1} x_i, где x_i и y_j — блоки по s байт.
    /// </summary>
    public static byte[] ApplyMatrixToVertexBlocks(bool[][] M, byte[] x, int n, int s)
    {
        int blockSize = n * s;
        if (x.Length != blockSize) throw new ArgumentException("x size mismatch.");

        var y = new byte[blockSize];

        for (int row = 0; row < n; row++)
        {
            int yOff = row * s;

            for (int col = 0; col < n; col++)
            {
                if (!M[row][col]) continue;

                int xOff = col * s;
                for (int k = 0; k < s; k++)
                    y[yOff + k] ^= x[xOff + k];
            }
        }

        return y;
    }
}