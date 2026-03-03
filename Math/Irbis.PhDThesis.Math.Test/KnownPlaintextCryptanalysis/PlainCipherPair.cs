namespace Irbis.PhDThesis.Math.Cryptanalysis.KnownPlaintext;

/// <summary>
/// Пара plaintext и ciphertext.
/// </summary>
public sealed record PlainCipherPair(byte[] Plaintext, byte[] Ciphertext);