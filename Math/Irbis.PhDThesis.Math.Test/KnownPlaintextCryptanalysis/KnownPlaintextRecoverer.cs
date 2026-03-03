using System;
using System.Collections.Generic;

namespace Irbis.PhDThesis.Math.Cryptanalysis.KnownPlaintext;

/// <summary>
/// Восстановление матрицы M из known-plaintext пар (P_i, C_i) без доступа к шифратору.
/// Здесь мы считаем, что шифр строго линейный:
///     C = M*P
/// (никакой константы c нет).
/// - строим разности ΔP = P_i XOR P_0 и ΔC = C_i XOR C_0
/// - получаем ΔC = M*ΔP
/// - восстанавливаем M как M = CΔ * (PΔ)^{-1} на одной битовой плоскости
/// </summary>
public static class KnownPlaintextRecoverer
{
    public sealed record RecoveredModel(
        bool[][] M,
        bool[][] Minv,
        int VerticesCount,
        int SmallBlockSizeBytes);

    public static RecoveredModel Recover(IReadOnlyList<PlainCipherPair> pairs, int n, int s, int maxValidationPairs = 50)
    {
        if (pairs == null) throw new ArgumentNullException(nameof(pairs));
        if (pairs.Count < 2) throw new ArgumentException("Нужно минимум 2 пары (P,C).", nameof(pairs));
        if (n <= 0) throw new ArgumentOutOfRangeException(nameof(n));
        if (s <= 0) throw new ArgumentOutOfRangeException(nameof(s));

        int blockSize = n * s;

        // Проверяем размеры
        for (int i = 0; i < pairs.Count; i++)
        {
            if (pairs[i].Plaintext == null || pairs[i].Ciphertext == null)
                throw new ArgumentException("Найдена пара с null plaintext/ciphertext.");

            if (pairs[i].Plaintext.Length != blockSize || pairs[i].Ciphertext.Length != blockSize)
                throw new ArgumentException("Размер блока в парах не равен n * smallBlockSizeBytes.");
        }

        // Базовая пара (P0,C0). Используем её только для построения разностей.
        byte[] P0 = pairs[0].Plaintext;
        byte[] C0 = pairs[0].Ciphertext;

        // ΔP_i = P_i XOR P0; ΔC_i = C_i XOR C0
        int m = pairs.Count - 1;
        var deltaP = new List<byte[]>(m);
        var deltaC = new List<byte[]>(m);

        for (int i = 1; i < pairs.Count; i++)
        {
            deltaP.Add(ByteXor.Xor(pairs[i].Plaintext, P0));
            deltaC.Add(ByteXor.Xor(pairs[i].Ciphertext, C0));
        }

        // Пробуем разные битовые плоскости внутри блока вершины: 0..8*s-1
        for (int bitPlane = 0; bitPlane < 8 * s; bitPlane++)
        {
            // На этой плоскости получаем уравнения cVec = M * pVec над GF(2)
            var pVectors = new bool[m][];
            var cVectors = new bool[m][];

            for (int i = 0; i < m; i++)
            {
                pVectors[i] = VertexBitPlane.ExtractVertexBits(deltaP[i], n, s, bitPlane);
                cVectors[i] = VertexBitPlane.ExtractVertexBits(deltaC[i], n, s, bitPlane);
            }

            // Выбираем n линейно независимых pVectors => PΔ обратима
            int[] chosen = IndependentVectorSelector.SelectIndices(pVectors, n, requiredRank: n);
            if (chosen.Length < n)
                continue;

            // Строим матрицы PΔ и CΔ из выбранных столбцов
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
                continue;
            }

            // M = CΔ * (PΔ)^{-1}
            bool[][] M = Gf2Matrix.Multiply(Cmat, Pinv);

            // Проверяем M на части данных (и на нескольких плоскостях для надёжности)
            if (!ValidateCandidateM(M, deltaP, deltaC, n, s, bitPlane, maxValidationPairs))
                continue;

            // M^{-1} для дешифрования
            bool[][] Minv = Gf2Matrix.Invert(M);

            return new RecoveredModel(M, Minv, n, s);
        }

        throw new InvalidOperationException(
            "Не удалось восстановить M по known-plaintext парам. " +
            "Возможные причины: мало пар, недостаточный ранг ΔP, пары не под одним ключом/режимом.");
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
        int tests = System.Math.Min(deltaP.Count, maxPairs);

        // Проверим на нескольких плоскостях: основной и паре соседних (без LINQ)
        int p1 = mainBitPlane;
        int p2 = System.Math.Min(mainBitPlane + 1, 8 * s - 1);
        int p3 = System.Math.Min(mainBitPlane + 7, 8 * s - 1);

        int[] planesTmp = new[] { p1, p2, p3 };
        int[] planes = UniqueInts3(planesTmp);

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

    private static int[] UniqueInts3(int[] a)
    {
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
    /// y = M*x на уровне "вершинных блоков" (каждая вершина = s байт):
    /// y_j = XOR_{i: M[j,i]=1} x_i
    /// </summary>
    public static byte[] ApplyMatrixToVertexBlocks(bool[][] M, byte[] x, int n, int s)
    {
        int blockSize = n * s;
        if (x.Length != blockSize) throw new ArgumentException("Неверный размер x.");

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