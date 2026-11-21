using System.Security.Cryptography;

namespace QuantumSafe.Crypto;

/// <summary>
/// Public-key encryption of a message: KEM for the key, AES-256-GCM for the data.
/// Wire format: version (1) | algorithm (1) | len-prefixed encapsulation | nonce (12) | tag (16) | ciphertext.
/// The header is authenticated as associated data, so the algorithm byte cannot be changed to force a downgrade.
/// </summary>
public static class Envelope
{
    private const byte Version = 1;
    private const int NonceSize = 12;
    private const int TagSize = 16;

    public static byte[] Seal(IKemScheme scheme, byte[] recipientPublicKey, byte[] plaintext, byte[]? associatedData = null)
    {
        ArgumentNullException.ThrowIfNull(scheme);
        ArgumentNullException.ThrowIfNull(plaintext);
        var kem = scheme.Encapsulate(recipientPublicKey);
        var header = WireFormat.Concat([Version, (byte)scheme.Algorithm], WireFormat.Join(kem.Encapsulation));
        var nonce = RandomNumberGenerator.GetBytes(NonceSize);
        var tag = new byte[TagSize];
        var ciphertext = new byte[plaintext.Length];
        using (var aes = new AesGcm(kem.SharedSecret, TagSize))
        {
            aes.Encrypt(nonce, plaintext, ciphertext, tag, Aad(header, associatedData));
        }

        CryptographicOperations.ZeroMemory(kem.SharedSecret);
        return WireFormat.Concat(header, nonce, tag, ciphertext);
    }

    public static byte[] Open(IKemRecipient recipient, byte[] envelope, byte[]? associatedData = null)
    {
        ArgumentNullException.ThrowIfNull(recipient);
        ArgumentNullException.ThrowIfNull(envelope);
        if (envelope.Length < 2 + 4 + NonceSize + TagSize || envelope[0] != Version)
        {
            throw new CryptographicException("Unsupported or truncated envelope.");
        }

        if (envelope[1] != (byte)recipient.Algorithm)
        {
            throw new CryptographicException($"Envelope algorithm {(KemAlgorithm)envelope[1]} does not match the recipient key ({recipient.Algorithm}).");
        }

        var encLen = System.Buffers.Binary.BinaryPrimitives.ReadInt32BigEndian(envelope.AsSpan(2));
        if (encLen < 0 || encLen > envelope.Length - (2 + 4 + NonceSize + TagSize))
        {
            throw new CryptographicException("Malformed envelope.");
        }

        var headerLen = 2 + 4 + encLen;

        var header = envelope.AsSpan(0, headerLen).ToArray();
        var encapsulation = envelope.AsSpan(6, encLen).ToArray();
        var nonce = envelope.AsSpan(headerLen, NonceSize);
        var tag = envelope.AsSpan(headerLen + NonceSize, TagSize);
        var ciphertext = envelope.AsSpan(headerLen + NonceSize + TagSize);
        var key = recipient.Decapsulate(encapsulation);
        var plaintext = new byte[ciphertext.Length];
        try
        {
            using var aes = new AesGcm(key, TagSize);
            aes.Decrypt(nonce, ciphertext, tag, plaintext, Aad(header, associatedData));
            return plaintext;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    private static byte[] Aad(byte[] header, byte[]? associatedData) =>
        WireFormat.Concat(header, associatedData ?? []);
}
