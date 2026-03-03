using System;

namespace Irbis.PhDThesis.Math.Cryptanalysis.KnownPlaintext;

/// <summary>
/// XOR для byte[] (GF(2) на уровне бит).
/// Xor с новым массивом.
/// XorInPlace запись в передаваемый target.
/// </summary>
public static class ByteXor
{
    public static byte[] Xor(byte[] a, byte[] b)
    {
        if (a == null) throw new ArgumentNullException(nameof(a));
        if (b == null) throw new ArgumentNullException(nameof(b));
        if (a.Length != b.Length) throw new ArgumentException("Length mismatch.");

        var r = new byte[a.Length];
        for (int i = 0; i < a.Length; i++)
            r[i] = (byte)(a[i] ^ b[i]);
        return r;
    }

    public static void XorInPlace(byte[] target, byte[] other)
    {
        if (target == null) throw new ArgumentNullException(nameof(target));
        if (other == null) throw new ArgumentNullException(nameof(other));
        if (target.Length != other.Length) throw new ArgumentException("Length mismatch.");

        for (int i = 0; i < target.Length; i++)
            target[i] ^= other[i];
    }
}