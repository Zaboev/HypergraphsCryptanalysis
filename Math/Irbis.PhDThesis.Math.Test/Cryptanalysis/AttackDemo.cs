using System;
using Irbis.PhDThesis.Math.Domain;
using Irbis.PhDThesis.Math.Encryption;

namespace Irbis.PhDThesis.Math.Cryptanalysis;

/// <summary>
/// Готовая демонстрация атаки для твоего шифра:
/// - строим M и M^{-1}
/// - шифруем случайный блок
/// - "взламываем" его без ключа
/// - проверяем совпадение.
/// </summary>
public static class AttackDemo
{
    public static void Run(HomogenousHypergraph key, int smallBlockSizeBytes, int seed = 12345)
    {
        int n = key.VerticesCount;
        var algorithm = new HomogenousHypergraphEncryptor(key, smallBlockSizeBytes);
        var oracle = new HomogenousHypergraphEncryptorOracle(algorithm);

        Console.WriteLine($"[AttackDemo] n={n}, smallBlockSizeBytes={smallBlockSizeBytes}, blockSizeBytes={oracle.BlockSizeBytes}");

        // 1) Восстановление M и M^{-1}
        Console.WriteLine("[AttackDemo] Recovering M and Minv...");
        var rec = VertexMatrixRecovery.Recover(oracle, n, smallBlockSizeBytes);

        // 2) Создаём взломанный дешифратор
        var hacked = new HackedDecryptor(rec);

        // 3) Тест на случайном блоке
        var rng = new Random(seed);
        var p = new byte[oracle.BlockSizeBytes];
        rng.NextBytes(p);

        var c = oracle.Encrypt(p);
        var pRecovered = hacked.Decrypt(c);

        Console.WriteLine("[AttackDemo] Plaintext == Recovered: " + p.AsSpan().SequenceEqual(pRecovered));
    }
}