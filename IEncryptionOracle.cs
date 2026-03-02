namespace Irbis.PhDThesis.Math.Cryptanalysis;

/// <summary>
/// Оракул шифрования для chosen-plaintext атаки.
/// Нам нужно уметь подавать выбранные plaintext и получать ciphertext фиксированного размера.
/// </summary>
public interface IEncryptionOracle
{
    int BlockSizeBytes { get; }

    byte[] Encrypt(byte[] plaintext);
}