namespace Irbis.PhDThesis.Math.Cryptanalysis.KnownPlaintext;

/// <summary>
/// Одна пара (plaintext, ciphertext) одного блока фиксированного размера.
/// </summary>
public sealed record PlainCipherPair(byte[] Plaintext, byte[] Ciphertext);