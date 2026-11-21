using System.Security.Cryptography;

namespace QuantumSafe.Crypto;

/// <summary>Result of encapsulating a fresh shared secret to a recipient's public key.</summary>
public sealed record KemResult(byte[] Encapsulation, byte[] SharedSecret);

/// <summary>A key-encapsulation scheme. Callers depend on this, not on a concrete algorithm (crypto-agility).</summary>
public interface IKemScheme
{
    KemAlgorithm Algorithm { get; }

    IKemRecipient GenerateRecipient();

    KemResult Encapsulate(byte[] recipientPublicKey);
}

/// <summary>The holder of a private key who can recover the shared secret.</summary>
public interface IKemRecipient : IDisposable
{
    KemAlgorithm Algorithm { get; }

    byte[] PublicKey { get; }

    byte[] Decapsulate(byte[] encapsulation);
}

public enum KemAlgorithm : byte
{
    EcdhP256 = 1,
    MlKem768 = 2,
    HybridEcdhP256MlKem768 = 3,
}

/// <summary>Classical ECDH on P-256, wrapped as a KEM. Quantum-vulnerable: kept for interop and fallback.</summary>
public sealed class EcdhP256Kem : IKemScheme
{
    internal const int SecretSize = 32;
    private static readonly byte[] Info = "QuantumSafe.EcdhP256Kem.v1"u8.ToArray();

    public KemAlgorithm Algorithm => KemAlgorithm.EcdhP256;

    public IKemRecipient GenerateRecipient() => new Recipient(ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256));

    public KemResult Encapsulate(byte[] recipientPublicKey)
    {
        ArgumentNullException.ThrowIfNull(recipientPublicKey);
        using var recipient = ECDiffieHellman.Create();
        recipient.ImportSubjectPublicKeyInfo(recipientPublicKey, out _);
        using var ephemeral = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var encapsulation = ephemeral.ExportSubjectPublicKeyInfo();
        var raw = ephemeral.DeriveRawSecretAgreement(recipient.PublicKey);
        return new KemResult(encapsulation, Derive(raw, encapsulation, recipientPublicKey));
    }

    private static byte[] Derive(byte[] raw, byte[] encapsulation, byte[] recipientPublicKey)
    {
        var info = WireFormat.Concat(Info, encapsulation, recipientPublicKey);
        var secret = HKDF.DeriveKey(HashAlgorithmName.SHA256, raw, SecretSize, salt: [], info: info);
        CryptographicOperations.ZeroMemory(raw);
        return secret;
    }

    private sealed class Recipient(ECDiffieHellman key) : IKemRecipient
    {
        public KemAlgorithm Algorithm => KemAlgorithm.EcdhP256;

        public byte[] PublicKey { get; } = key.ExportSubjectPublicKeyInfo();

        public byte[] Decapsulate(byte[] encapsulation)
        {
            ArgumentNullException.ThrowIfNull(encapsulation);
            using var ephemeral = ECDiffieHellman.Create();
            ephemeral.ImportSubjectPublicKeyInfo(encapsulation, out _);
            var raw = key.DeriveRawSecretAgreement(ephemeral.PublicKey);
            return Derive(raw, encapsulation, PublicKey);
        }

        public void Dispose() => key.Dispose();
    }
}

/// <summary>ML-KEM-768 (NIST FIPS 203) using the .NET 10 platform implementation.</summary>
public sealed class MlKem768Kem : IKemScheme
{
    public KemAlgorithm Algorithm => KemAlgorithm.MlKem768;

    public IKemRecipient GenerateRecipient()
    {
        PqcSupport.EnsureMlKem();
        return new Recipient(MLKem.GenerateKey(MLKemAlgorithm.MLKem768));
    }

    public KemResult Encapsulate(byte[] recipientPublicKey)
    {
        ArgumentNullException.ThrowIfNull(recipientPublicKey);
        PqcSupport.EnsureMlKem();
        using var recipient = MLKem.ImportEncapsulationKey(MLKemAlgorithm.MLKem768, recipientPublicKey);
        recipient.Encapsulate(out var ciphertext, out var sharedSecret);
        return new KemResult(ciphertext, sharedSecret);
    }

    private sealed class Recipient(MLKem key) : IKemRecipient
    {
        public KemAlgorithm Algorithm => KemAlgorithm.MlKem768;

        public byte[] PublicKey { get; } = key.ExportEncapsulationKey();

        public byte[] Decapsulate(byte[] encapsulation)
        {
            ArgumentNullException.ThrowIfNull(encapsulation);
            return key.Decapsulate(encapsulation);
        }

        public void Dispose() => key.Dispose();
    }
}

/// <summary>
/// Hybrid KEM: ECDH P-256 and ML-KEM-768 together. The session key stays safe as long as either
/// component holds, which is the transition approach NIST IR 8547 allows while PQC implementations mature.
/// The combiner hashes both secrets with both ciphertexts and both public keys, so neither part can be
/// swapped or replayed on its own.
/// </summary>
public sealed class HybridKem : IKemScheme
{
    private const int SecretSize = 32;
    private static readonly byte[] Label = "QuantumSafe.HybridKem.EcdhP256+MlKem768.v1"u8.ToArray();
    private readonly EcdhP256Kem _classical = new();
    private readonly MlKem768Kem _pq = new();

    public KemAlgorithm Algorithm => KemAlgorithm.HybridEcdhP256MlKem768;

    public IKemRecipient GenerateRecipient()
    {
        PqcSupport.EnsureMlKem();
        return new Recipient(_classical.GenerateRecipient(), _pq.GenerateRecipient());
    }

    public KemResult Encapsulate(byte[] recipientPublicKey)
    {
        var parts = WireFormat.Split(recipientPublicKey, 2);
        var c = _classical.Encapsulate(parts[0]);
        var q = _pq.Encapsulate(parts[1]);
        var encapsulation = WireFormat.Join(c.Encapsulation, q.Encapsulation);
        return new KemResult(encapsulation, Combine(c.SharedSecret, q.SharedSecret, encapsulation, recipientPublicKey));
    }

    internal static byte[] Combine(byte[] classical, byte[] pq, byte[] encapsulation, byte[] publicKey)
    {
        var ikm = WireFormat.Concat(classical, pq);
        var info = WireFormat.Concat(Label, encapsulation, publicKey);
        var secret = HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, SecretSize, salt: [], info: info);
        CryptographicOperations.ZeroMemory(ikm);
        CryptographicOperations.ZeroMemory(classical);
        CryptographicOperations.ZeroMemory(pq);
        return secret;
    }

    private sealed class Recipient(IKemRecipient classical, IKemRecipient pq) : IKemRecipient
    {
        public KemAlgorithm Algorithm => KemAlgorithm.HybridEcdhP256MlKem768;

        public byte[] PublicKey { get; } = WireFormat.Join(classical.PublicKey, pq.PublicKey);

        public byte[] Decapsulate(byte[] encapsulation)
        {
            var parts = WireFormat.Split(encapsulation, 2);
            var c = classical.Decapsulate(parts[0]);
            var q = pq.Decapsulate(parts[1]);
            return Combine(c, q, encapsulation, PublicKey);
        }

        public void Dispose()
        {
            classical.Dispose();
            pq.Dispose();
        }
    }
}
