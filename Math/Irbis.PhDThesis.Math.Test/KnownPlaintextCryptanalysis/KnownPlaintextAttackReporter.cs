using System;
using System.Text;

namespace Irbis.PhDThesis.Math.Cryptanalysis.KnownPlaintext;

public static class KnownPlaintextAttackReporter
{
    public static void PrintReport(
        IReadOnlyList<PlainCipherPair> pairs,
        KnownPlaintextRecoverer.RecoveredModel model,
        int pairIndexToShow,
        int traceVertices = 8,
        int maxTermsToShow = 20,
        int maxVerticesToPrint = 16)
    {
        if (pairs == null) throw new ArgumentNullException(nameof(pairs));
        if (model == null) throw new ArgumentNullException(nameof(model));
        if (pairIndexToShow < 0 || pairIndexToShow >= pairs.Count) throw new ArgumentOutOfRangeException(nameof(pairIndexToShow));

        int n = model.VerticesCount;
        int s = model.SmallBlockSizeBytes;
        int blockSize = n * s;

        var pair = pairs[pairIndexToShow];
        var P = pair.Plaintext;
        var C = pair.Ciphertext;

        Console.WriteLine("====================================================");
        Console.WriteLine("ОТЧЁТ: KNOWN-PLAINTEXT АТАКА (ВОССТАНОВЛЕНИЕ БЕЗ КЛЮЧА)");
        Console.WriteLine("====================================================");
        Console.WriteLine($"Число вершин (n)                 = {n}");
        Console.WriteLine($"Размер малого блока на вершину   = {s} байт");
        Console.WriteLine($"Размер всего блока               = {blockSize} байт");
        Console.WriteLine($"Количество имеющихся пар (P,C)   = {pairs.Count}");
        Console.WriteLine($"Показываем пару с индексом       = {pairIndexToShow}");
        Console.WriteLine();

        // 1) Исходный plaintext
        Console.WriteLine("1) ОТКРЫТЫЙ ТЕКСТ (plaintext) — исходные данные по вершинам");
        PrintBlockByVertices(P, n, s, maxVerticesToPrint);

        // 2) Ciphertext
        Console.WriteLine("\n2) ШИФРОТЕКСТ (ciphertext) — результат шифрования по вершинам");
        PrintBlockByVertices(C, n, s, maxVerticesToPrint);

        // 3) Константа c
        Console.WriteLine("\n3) ВОССТАНОВЛЕННАЯ КОНСТАНТА c в модели C = M*P XOR c");
        Console.WriteLine("   (часто это нули; если не нули — значит в реализации есть аффинный сдвиг)");
        PrintBlockByVertices(model.C, n, s, maxVerticesToPrint);

        // 4) C' = C XOR c
        var Cprime = ByteXor.Xor(C, model.C);
        Console.WriteLine("\n4) ПРОМЕЖУТОЧНОЕ: C' = C XOR c");
        Console.WriteLine("   (именно C' мы подаём на умножение на обратную матрицу M^{-1})");
        PrintBlockByVertices(Cprime, n, s, maxVerticesToPrint);

        // 5) Расшифрование через Minv
        Console.WriteLine("\n5) ВОССТАНОВЛЕНИЕ (расшифрование) через обратную матрицу M^{-1}:");
        Console.WriteLine("   Формула: P = M^{-1} * (C XOR c)");
        var hacked = new KnownPlaintextHackedDecryptor(model);
        var Precovered = hacked.Decrypt(C);

        Console.WriteLine("\n6) ВОССТАНОВЛЕННЫЙ ОТКРЫТЫЙ ТЕКСТ (plaintext) по вершинам");
        PrintBlockByVertices(Precovered, n, s, maxVerticesToPrint);

        bool ok = EqualBytes(P, Precovered);
        Console.WriteLine($"\n7) ПРОВЕРКА: восстановленный plaintext == исходный plaintext : {ok}");

        // 6) Трассировка XOR по строкам Minv
        int showTrace = System.Math.Min(traceVertices, n);
        Console.WriteLine("\n8) ПОЯСНЕНИЕ МЕХАНИКИ ВОССТАНОВЛЕНИЯ (какие блоки ксорятся):");
        Console.WriteLine($"   Покажем первые {showTrace} вершин(ы).");
        Console.WriteLine("   Каждая строка означает:");
        Console.WriteLine("   P[i] = XOR по тем C'[j], где M^{-1}[i][j] = 1");
        Console.WriteLine("   (то есть берём некоторые вершины из C' и ксорим их блоки байт)");
        Console.WriteLine();

        PrintDecryptionTrace(model.Minv, Cprime, n, s, traceVertices, maxTermsToShow);

        Console.WriteLine("====================================================\n");
    }

    private static void PrintDecryptionTrace(
        bool[][] Minv,
        byte[] Cprime,
        int n,
        int s,
        int traceVertices,
        int maxTermsToShow)
    {
        int showV = System.Math.Min(traceVertices, n);

        for (int i = 0; i < showV; i++)
        {
            // список j, которые участвуют (M^{-1}[i][j] = 1)
            int[] terms = CollectTerms(Minv[i], maxTermsToShow, out int totalTerms);

            // считаем блок plaintext вершины i вручную (чтобы было явно видно, что это XOR)
            var pi = new byte[s];
            for (int t = 0; t < terms.Length; t++)
            {
                int j = terms[t];
                int off = j * s;
                for (int k = 0; k < s; k++)
                    pi[k] ^= Cprime[off + k];
            }

            var sb = new StringBuilder();
            sb.Append($"P[{i}] = XOR из {totalTerms} блока(ов): ");

            if (totalTerms == 0)
            {
                sb.Append("(ничего не ксорим) => ");
            }
            else
            {
                sb.Append("C'[");
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

    private static void PrintBlockByVertices(byte[] block, int n, int s, int maxVerticesToPrint)
    {
        if (block == null) throw new ArgumentNullException(nameof(block));
        if (block.Length != n * s) throw new ArgumentException("Размер блока не равен n * smallBlockSize.");

        int show = System.Math.Min(n, maxVerticesToPrint);

        Console.WriteLine($"   Показано {show} вершинных блоков из {n} всего:");
        for (int i = 0; i < show; i++)
        {
            int off = i * s;
            var vb = new byte[s];
            Array.Copy(block, off, vb, 0, s);
            Console.WriteLine($"   вершина v[{i:000}] : {BlockHex(vb)}");
        }

        if (show < n)
            Console.WriteLine("   ... (остальные вершины скрыты, чтобы не засорять вывод)");
    }

    private static string BlockHex(byte[] bytes)
    {
        var sb = new StringBuilder(bytes.Length * 2 + 8);
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