using System;

namespace Irbis.PhDThesis.Math.Cryptanalysis;

/// <summary>
/// Инверсия бинарной матрицы bool[n][n] методом Гаусса–Жордана над GF(2).
/// Операции:
/// - сложение строк = XOR
/// - умножение на 1/0 тривиально
/// </summary>
public static class Gf2GaussJordan
{
    public static bool[][] Invert(bool[][] a)
    {
        if (a == null) throw new ArgumentNullException(nameof(a));
        int n = a.Length;
        if (n == 0) throw new ArgumentException("Empty matrix.");

        for (int i = 0; i < n; i++)
            if (a[i] == null || a[i].Length != n)
                throw new ArgumentException("Matrix must be square (n x n).");

        // augmented = [A | I]
        var aug = new bool[n][];
        for (int i = 0; i < n; i++)
        {
            aug[i] = new bool[2 * n];
            Array.Copy(a[i], 0, aug[i], 0, n);
            aug[i][n + i] = true;
        }

        // Gauss–Jordan elimination over GF(2)
        for (int col = 0; col < n; col++)
        {
            int pivot = -1;
            for (int row = col; row < n; row++)
            {
                if (aug[row][col])
                {
                    pivot = row;
                    break;
                }
            }

            if (pivot == -1)
                throw new InvalidOperationException("Matrix is singular (not invertible).");

            if (pivot != col)
            {
                var tmp = aug[col];
                aug[col] = aug[pivot];
                aug[pivot] = tmp;
            }

            for (int row = 0; row < n; row++)
            {
                if (row == col) continue;
                if (!aug[row][col]) continue;

                // row = row XOR pivotRow
                for (int j = 0; j < 2 * n; j++)
                    aug[row][j] ^= aug[col][j];
            }
        }

        // Extract inverse from right half
        var inv = new bool[n][];
        for (int i = 0; i < n; i++)
        {
            inv[i] = new bool[n];
            Array.Copy(aug[i], n, inv[i], 0, n);
        }

        return inv;
    }
}