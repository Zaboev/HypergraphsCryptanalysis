using System;

namespace Irbis.PhDThesis.Math.Cryptanalysis.KnownPlaintext;

/// <summary>
/// Бинарная матрица над GF(2) в виде bool[n][n] (строки).
/// Здесь инверсия Гаусс–Жорданом и умножения.
/// </summary>
public static class Gf2Matrix
{
    public static bool[][] NewZero(int n)
    {
        var m = new bool[n][];
        for (int i = 0; i < n; i++) m[i] = new bool[n];
        return m;
    }

    /// <summary>Создать матрицу из списка столбцов cols (каждый bool[n]).</summary>
    public static bool[][] FromColumns(bool[][] cols)
    {
        int n = cols.Length;
        for (int c = 0; c < n; c++)
            if (cols[c].Length != n)
                throw new ArgumentException("Column length mismatch.");

        var m = NewZero(n);
        for (int col = 0; col < n; col++)
            for (int row = 0; row < n; row++)
                m[row][col] = cols[col][row];

        return m;
    }

    public static bool[] Multiply(bool[][] a, bool[] x)
    {
        int n = a.Length;
        var y = new bool[n];

        for (int i = 0; i < n; i++)
        {
            bool sum = false;
            var row = a[i];
            for (int j = 0; j < n; j++)
                if (row[j] && x[j]) sum ^= true;
            y[i] = sum;
        }

        return y;
    }

    /// <summary>Умножение матриц: c = a*b.</summary>
    public static bool[][] Multiply(bool[][] a, bool[][] b)
    {
        int n = a.Length;
        var c = NewZero(n);

        for (int i = 0; i < n; i++)
        {
            for (int k = 0; k < n; k++)
            {
                if (!a[i][k]) continue;
                // c[i,*] ^= b[k,*]
                for (int j = 0; j < n; j++)
                    c[i][j] ^= b[k][j];
            }
        }

        return c;
    }

    /// <summary>
    /// Инверсия методом Гаусса–Жордана над GF(2).
    /// Бросает исключение, если матрица вырожденная.
    /// </summary>
    public static bool[][] Invert(bool[][] a)
    {
        if (a == null) throw new ArgumentNullException(nameof(a));
        int n = a.Length;
        for (int i = 0; i < n; i++)
            if (a[i] == null || a[i].Length != n)
                throw new ArgumentException("Matrix must be square (n x n).");

        // aug = [A | I]
        var aug = new bool[n][];
        for (int i = 0; i < n; i++)
        {
            aug[i] = new bool[2 * n];
            Array.Copy(a[i], 0, aug[i], 0, n);
            aug[i][n + i] = true;
        }

        for (int col = 0; col < n; col++)
        {
            int pivot = -1;
            for (int row = col; row < n; row++)
            {
                if (aug[row][col]) { pivot = row; break; }
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

                for (int j = 0; j < 2 * n; j++)
                    aug[row][j] ^= aug[col][j];
            }
        }

        var inv = new bool[n][];
        for (int i = 0; i < n; i++)
        {
            inv[i] = new bool[n];
            Array.Copy(aug[i], n, inv[i], 0, n);
        }

        return inv;
    }
}