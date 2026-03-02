using System;
using System.Collections.Generic;

namespace Irbis.PhDThesis.Math.Cryptanalysis.KnownPlaintext;

/// <summary>
/// Выбирает линейно независимые векторы bool[n] над GF(2) из потока кандидатов.
/// Это нужно, чтобы из known-plaintext данных собрать "инвертируемую" матрицу PΔ.
/// </summary>
public sealed class IndependentVectorSelector
{
    private readonly int _n;
    private readonly bool[][] _basis;   // basis[pivot] = вектор с ведущей 1 в pivot
    private readonly bool[] _hasBasis;
    public int Rank { get; private set; }

    public IndependentVectorSelector(int n)
    {
        if (n <= 0) throw new ArgumentOutOfRangeException(nameof(n));
        _n = n;
        _basis = new bool[n][];
        _hasBasis = new bool[n];
    }

    /// <summary>
    /// Пытается добавить вектор v в базис.
    /// Возвращает true, если v увеличил ранг (т.е. был независимым).
    /// </summary>
    public bool TryAdd(bool[] v)
    {
        if (v == null) throw new ArgumentNullException(nameof(v));
        if (v.Length != _n) throw new ArgumentException("Vector length mismatch.");

        var w = (bool[])v.Clone();

        for (int pivot = 0; pivot < _n; pivot++)
        {
            if (!w[pivot]) continue;

            if (_hasBasis[pivot])
            {
                // w ^= basis[pivot]
                var b = _basis[pivot];
                for (int i = pivot; i < _n; i++)
                    w[i] ^= b[i];
                continue;
            }

            // новый базисный вектор
            _basis[pivot] = w;
            _hasBasis[pivot] = true;
            Rank++;
            return true;
        }

        return false;
    }

    public static int[] SelectIndices(IReadOnlyList<bool[]> candidates, int n, int requiredRank)
    {
        var sel = new List<int>(requiredRank);
        var s = new IndependentVectorSelector(n);

        for (int i = 0; i < candidates.Count && s.Rank < requiredRank; i++)
        {
            if (s.TryAdd(candidates[i]))
                sel.Add(i);
        }

        return sel.ToArray();
    }
}