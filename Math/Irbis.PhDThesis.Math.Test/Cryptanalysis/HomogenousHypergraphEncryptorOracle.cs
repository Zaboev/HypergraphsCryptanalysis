using System;
using Irbis.PhDThesis.Math.Encryption;

namespace Irbis.PhDThesis.Math.Cryptanalysis;

/// <summary>
/// Адаптер под твою реализацию HomogenousHypergraphEncryptor.
/// Мы вызываем алгоритм напрямую (algorithm.Encrypt), без CryptoTransformationContext,
/// чтобы анализировать именно "ядро блочного шифра" (ECB на одном блоке).
///
/// Важно:
/// HomogenousHypergraphEncryptor.BlockSize = VerticesCount * smallBlockSize (в байтах). :contentReference[oaicite:5]{index=5}
/// </summary>
public sealed class HomogenousHypergraphEncryptorOracle : IEncryptionOracle
{
    private readonly HomogenousHypergraphEncryptor _algorithm;

    public int BlockSizeBytes => _algorithm.BlockSize;

    public HomogenousHypergraphEncryptorOracle(HomogenousHypergraphEncryptor algorithm)
    {
        _algorithm = algorithm ?? throw new ArgumentNullException(nameof(algorithm));
    }

    public byte[] Encrypt(byte[] plaintext)
    {
        if (plaintext == null) throw new ArgumentNullException(nameof(plaintext));
        if (plaintext.Length != BlockSizeBytes)
            throw new ArgumentException($"Plaintext must have length {BlockSizeBytes} bytes.");

        byte[]? output = null;
        _algorithm.Encrypt(plaintext, ref output);
        return output!;
    }
}