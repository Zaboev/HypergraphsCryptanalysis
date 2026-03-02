using System;

namespace Irbis.PhDThesis.Math.Cryptanalysis;

/// <summary>
/// Утилиты работы с "вершинными блоками":
/// состояние = n вершин, каждая вершина занимает smallBlockSize байт.
/// Мы постоянно берём подмассивы вида data[offset .. offset+smallBlockSize).
///
/// Зачем:
/// - восстановление матрицы M делается по принципу "одна вершина активна → смотрим, какие выходные вершины стали активны".
/// - дешифрование = XOR нужных вершинных блоков.
/// </summary>
public static class ByteBlockUtils
{
    public static void FillPattern(Span<byte> block, byte value)
    {
        for (int i = 0; i < block.Length; i++) block[i] = value;
    }

    public static bool IsAllZero(ReadOnlySpan<byte> block)
    {
        for (int i = 0; i < block.Length; i++)
            if (block[i] != 0) return false;
        return true;
    }

    public static bool SequenceEqual(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        if (a.Length != b.Length) return false;
        for (int i = 0; i < a.Length; i++)
            if (a[i] != b[i]) return false;
        return true;
    }

    public static void XorInto(Span<byte> into, ReadOnlySpan<byte> from)
    {
        if (into.Length != from.Length) throw new ArgumentException("Length mismatch.");
        for (int i = 0; i < into.Length; i++)
            into[i] ^= from[i];
    }
}