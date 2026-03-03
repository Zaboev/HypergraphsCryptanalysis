using System;
using System.Text;

namespace Irbis.PhDThesis.Math.Cryptanalysis.KnownPlaintext;

///<summary>
///Демонстрация.
///</summary>

public static class KnownPlaintextAttackReporter
{
    public static void PrintReport(
        IReadOnlyList<PlainCipherPair> pairs,
        KnownPlaintextRecoverer.RecoveredModel model,
        int pairIndexToShow,
        int verticesToPrint = 8,
        int traceForVertexIndex = 0,
        int maxTermsToShow = 12)
    {
        if (pairs == null) throw new ArgumentNullException(nameof(pairs));
        if (model == null) throw new ArgumentNullException(nameof(model));
        if (pairIndexToShow < 0 || pairIndexToShow >= pairs.Count) throw new ArgumentOutOfRangeException(nameof(pairIndexToShow));

        int n = model.VerticesCount;
        int s = model.SmallBlockSizeBytes;

        var pair = pairs[pairIndexToShow];
        var P = pair.Plaintext;
        var C = pair.Ciphertext;

        var hacked = new KnownPlaintextHackedDecryptor(model);
        var Precovered = hacked.Decrypt(C);

        bool ok = EqualBytes(P, Precovered);

        Console.WriteLine("=== KNOWN-PLAINTEXT (краткий отчёт) ===");
        Console.WriteLine($"n = {n}, s = {s} байт, блок = {n * s} байт, пара #{pairIndexToShow}, проверка = {(ok ? "OK" : "FAIL")}");
        Console.WriteLine();

        int show = System.Math.Min(verticesToPrint, n);

        Console.WriteLine($"PLAINTEXT (первые {show} вершин):");
        PrintBlockByVertices(P, n, s, show);

        Console.WriteLine($"\nCIPHERTEXT (первые {show} вершин):");
        PrintBlockByVertices(C, n, s, show);

        Console.WriteLine($"\nRECOVERED PLAINTEXT (первые {show} вершин):");
        PrintBlockByVertices(Precovered, n, s, show);

        // Короткая демонстрация, что восстановление идёт XOR'ом блоков ciphertext по строке Minv
        if (traceForVertexIndex >= 0 && traceForVertexIndex < n)
        {
            Console.WriteLine();
            PrintSingleVertexTrace(model.Minv, C, n, s, traceForVertexIndex, maxTermsToShow);
        }

        Console.WriteLine("======================================\n");
    }

    private static void PrintSingleVertexTrace(bool[][] Minv, byte[] C, int n, int s, int i, int maxTermsToShow)
    {
        int[] terms = CollectTerms(Minv[i], maxTermsToShow, out int totalTerms);

        // P[i] = XOR C[terms]
        var pi = new byte[s];
        for (int t = 0; t < terms.Length; t++)
        {
            int j = terms[t];
            int off = j * s;
            for (int k = 0; k < s; k++)
                pi[k] ^= C[off + k];
        }

        var sb = new StringBuilder();
        sb.Append($"Пример восстановления: P[{i}] = XOR ");

        if (totalTerms == 0)
        {
            sb.Append("(ничего) => ");
        }
        else
        {
            sb.Append("C[");
            for (int t = 0; t < terms.Length; t++)
            {
                if (t > 0) sb.Append(", ");
                sb.Append(terms[t]);
            }
            if (totalTerms > terms.Length) sb.Append(", ...");
            sb.Append("] => ");
        }

        sb.Append(BlockHex(pi));
        Console.WriteLine(sb.ToString());
    }

    private static int[] CollectTerms(bool[] row, int maxTermsToShow, out int total)
    {
        total = 0;
        for (int j = 0; j < row.Length; j++)
            if (row[j]) total++;

        int take = System.Math.Min(total, maxTermsToShow);
        var terms = new int[take];

        int idx = 0;
        for (int j = 0; j < row.Length && idx < take; j++)
        {
            if (!row[j]) continue;
            terms[idx++] = j;
        }

        return terms;
    }

    private static void PrintBlockByVertices(byte[] block, int n, int s, int show)
    {
        if (block == null) throw new ArgumentNullException(nameof(block));
        if (block.Length != n * s) throw new ArgumentException("Размер блока не равен n * smallBlockSize.");

        for (int i = 0; i < show; i++)
        {
            int off = i * s;
            var vb = new byte[s];
            Array.Copy(block, off, vb, 0, s);
            Console.WriteLine($"  v[{i:000}] {BlockHex(vb)}");
        }
    }

    private static string BlockHex(byte[] bytes)
    {
        var sb = new StringBuilder(bytes.Length * 2 + 2);
        sb.Append("0x");
        for (int i = 0; i < bytes.Length; i++)
            sb.Append(bytes[i].ToString("X2"));
        return sb.ToString();
    }

    private static bool EqualBytes(byte[] a, byte[] b)
    {
        if (a.Length != b.Length) return false;
        for (int i = 0; i < a.Length; i++)
            if (a[i] != b[i]) return false;
        return true;
    }
}