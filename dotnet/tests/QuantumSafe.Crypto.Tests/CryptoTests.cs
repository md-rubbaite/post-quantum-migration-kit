using System.Security.Cryptography;
using QuantumSafe.Crypto;

namespace QuantumSafe.Crypto.Tests;

/// <summary>
/// Post-quantum tests need platform support (.NET 10 with OpenSSL 3.5+ or a PQC-capable Windows CNG).
/// Where support is missing they return early, unless REQUIRE_PQC=true, which CI sets on the runner
/// that is expected to have PQC so a regression cannot pass silently.
/// </summary>
internal static class Pqc
{
    public static bool Ready(bool available)
    {
        if (available)
        {
            return true;
        }

        Assert.False(
            string.Equals(Environment.GetEnvironmentVariable("REQUIRE_PQC"), "true", StringComparison.OrdinalIgnoreCase),
            "REQUIRE_PQC=true but post-quantum algorithms are not available on this runner.");
        return false;
    }
}

public class ClassicalKemTests
{
    [Fact]
    public void Ecdh_roundtrip_agrees_on_the_same_secret()
    {
        var kem = new EcdhP256Kem();
        using var recipient = kem.GenerateRecipient();
        var sent = kem.Encapsulate(recipient.PublicKey);
        Assert.Equal(sent.SharedSecret, recipient.Decapsulate(sent.Encapsulation));
        Assert.Equal(32, sent.SharedSecret.Length);
    }

    [Fact]
    public void Each_encapsulation_produces_a_fresh_secret()
    {
        var kem = new EcdhP256Kem();
        using var recipient = kem.GenerateRecipient();
        Assert.NotEqual(kem.Encapsulate(recipient.PublicKey).SharedSecret, kem.Encapsulate(recipient.PublicKey).SharedSecret);
    }

    [Fact]
    public void Envelope_roundtrip_with_associated_data()
    {
        var kem = new EcdhP256Kem();
        using var recipient = kem.GenerateRecipient();
        var aad = "order-42"u8.ToArray();
        var sealedMessage = Envelope.Seal(kem, recipient.PublicKey, "card token"u8.ToArray(), aad);
        Assert.Equal("card token"u8.ToArray(), Envelope.Open(recipient, sealedMessage, aad));
    }

    [Fact]
    public void Envelope_rejects_tampered_ciphertext_and_wrong_associated_data()
    {
        var kem = new EcdhP256Kem();
        using var recipient = kem.GenerateRecipient();
        var sealedMessage = Envelope.Seal(kem, recipient.PublicKey, "hello"u8.ToArray(), "a"u8.ToArray());

        var tampered = (byte[])sealedMessage.Clone();
        tampered[^1] ^= 0x01;
        Assert.ThrowsAny<CryptographicException>(() => Envelope.Open(recipient, tampered, "a"u8.ToArray()));
        Assert.ThrowsAny<CryptographicException>(() => Envelope.Open(recipient, sealedMessage, "b"u8.ToArray()));
    }

    [Fact]
    public void Envelope_rejects_algorithm_downgrade_in_header()
    {
        var kem = new EcdhP256Kem();
        using var recipient = kem.GenerateRecipient();
        var sealedMessage = Envelope.Seal(kem, recipient.PublicKey, "hello"u8.ToArray());
        sealedMessage[1] = (byte)KemAlgorithm.HybridEcdhP256MlKem768;
        var ex = Assert.ThrowsAny<CryptographicException>(() => Envelope.Open(recipient, sealedMessage));
        Assert.Contains("does not match", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Envelope_rejects_truncated_input()
    {
        var kem = new EcdhP256Kem();
        using var recipient = kem.GenerateRecipient();
        Assert.ThrowsAny<CryptographicException>(() => Envelope.Open(recipient, [1, 1, 0]));
    }

    [Fact]
    public void Ecdsa_signatures_verify_and_detect_tampering()
    {
        using var signer = Signers.Create(SignatureAlgorithm.EcdsaP256);
        var data = "release v1.0.0"u8.ToArray();
        var sig = signer.Sign(data);
        Assert.True(Signers.Verify(SignatureAlgorithm.EcdsaP256, signer.PublicKey, data, sig));
        Assert.False(Signers.Verify(SignatureAlgorithm.EcdsaP256, signer.PublicKey, "release v1.0.1"u8.ToArray(), sig));
    }
}

public class WireFormatTests
{
    [Fact]
    public void Join_and_split_roundtrip()
    {
        var joined = WireFormat.Join([1, 2], [], [3]);
        var parts = WireFormat.Split(joined, 3);
        Assert.Equal(new byte[] { 1, 2 }, parts[0]);
        Assert.Empty(parts[1]);
        Assert.Equal(new byte[] { 3 }, parts[2]);
    }

    [Theory]
    [InlineData(new byte[] { 0, 0, 0 })]
    [InlineData(new byte[] { 0, 0, 0, 9, 1 })]
    [InlineData(new byte[] { 0x80, 0, 0, 0 })]
    public void Split_rejects_malformed_input(byte[] data) =>
        Assert.ThrowsAny<CryptographicException>(() => WireFormat.Split(data, 1));

    [Fact]
    public void Split_rejects_wrong_part_count() =>
        Assert.ThrowsAny<CryptographicException>(() => WireFormat.Split(WireFormat.Join([1], [2]), 3));
}

public class PolicyTests
{
    [Fact]
    public void Hybrid_is_used_when_available()
    {
        var d = new CryptoPolicy().Resolve(postQuantumAvailable: true);
        Assert.Equal(KeyEstablishmentMode.Hybrid, d.Mode);
        Assert.False(d.Downgraded);
        Assert.IsType<HybridKem>(d.CreateScheme());
    }

    [Fact]
    public void Unavailable_pqc_downgrades_visibly_by_default()
    {
        var d = new CryptoPolicy().Resolve(postQuantumAvailable: false);
        Assert.Equal(KeyEstablishmentMode.Classical, d.Mode);
        Assert.True(d.Downgraded);
        Assert.IsType<EcdhP256Kem>(d.CreateScheme());
    }

    [Fact]
    public void Required_pqc_fails_closed_when_unavailable() =>
        Assert.Throws<PostQuantumUnavailableException>(
            () => new CryptoPolicy(KeyEstablishmentMode.PostQuantumOnly, RequirePostQuantum: true).Resolve(postQuantumAvailable: false));

    [Fact]
    public void Requiring_pqc_while_preferring_classical_is_a_configuration_error() =>
        Assert.Throws<InvalidOperationException>(
            () => new CryptoPolicy(KeyEstablishmentMode.Classical, RequirePostQuantum: true).Resolve(postQuantumAvailable: true));

    [Fact]
    public void PostQuantumOnly_maps_to_ml_kem() =>
        Assert.IsType<MlKem768Kem>(new CryptoPolicy(KeyEstablishmentMode.PostQuantumOnly).Resolve(true).CreateScheme());
}

public class PostQuantumTests
{
    [Fact]
    public void MlKem_roundtrip()
    {
        if (!Pqc.Ready(PqcSupport.MlKemAvailable))
        {
            return;
        }

        var kem = new MlKem768Kem();
        using var recipient = kem.GenerateRecipient();
        Assert.Equal(1184, recipient.PublicKey.Length); // ML-KEM-768 encapsulation key (FIPS 203)
        var sent = kem.Encapsulate(recipient.PublicKey);
        Assert.Equal(1088, sent.Encapsulation.Length); // ML-KEM-768 ciphertext
        Assert.Equal(sent.SharedSecret, recipient.Decapsulate(sent.Encapsulation));
    }

    [Fact]
    public void Hybrid_roundtrip_through_envelope()
    {
        if (!Pqc.Ready(PqcSupport.MlKemAvailable))
        {
            return;
        }

        var kem = new HybridKem();
        using var recipient = kem.GenerateRecipient();
        var sealedMessage = Envelope.Seal(kem, recipient.PublicKey, "harvest-now-decrypt-later resistant"u8.ToArray());
        Assert.Equal((byte)KemAlgorithm.HybridEcdhP256MlKem768, sealedMessage[1]);
        Assert.Equal("harvest-now-decrypt-later resistant"u8.ToArray(), Envelope.Open(recipient, sealedMessage));
    }

    [Fact]
    public void Hybrid_secret_depends_on_both_components()
    {
        if (!Pqc.Ready(PqcSupport.MlKemAvailable))
        {
            return;
        }

        var kem = new HybridKem();
        using var recipient = kem.GenerateRecipient();
        var sent = kem.Encapsulate(recipient.PublicKey);
        var parts = WireFormat.Split(sent.Encapsulation, 2);

        // Replace the classical half with a fresh, valid ECDH encapsulation for the same recipient.
        var classicalPublic = WireFormat.Split(recipient.PublicKey, 2)[0];
        var otherClassical = new EcdhP256Kem().Encapsulate(classicalPublic).Encapsulation;
        var mixed = WireFormat.Join(otherClassical, parts[1]);
        Assert.NotEqual(sent.SharedSecret, recipient.Decapsulate(mixed));
        Assert.Equal(sent.SharedSecret, recipient.Decapsulate(sent.Encapsulation));
    }

    [Fact]
    public void MlDsa_signatures_verify_and_detect_tampering()
    {
        if (!Pqc.Ready(PqcSupport.MlDsaAvailable))
        {
            return;
        }

        using var signer = Signers.Create(SignatureAlgorithm.MlDsa65);
        Assert.Equal(1952, signer.PublicKey.Length); // ML-DSA-65 public key (FIPS 204)
        var data = "firmware image"u8.ToArray();
        var sig = signer.Sign(data);
        Assert.Equal(3309, sig.Length);
        Assert.True(Signers.Verify(SignatureAlgorithm.MlDsa65, signer.PublicKey, data, sig));
        sig[0] ^= 0x01;
        Assert.False(Signers.Verify(SignatureAlgorithm.MlDsa65, signer.PublicKey, data, sig));
    }

    [Fact]
    public void Unavailable_platform_reports_a_clear_error()
    {
        if (PqcSupport.MlKemAvailable)
        {
            return;
        }

        Assert.Throws<PostQuantumUnavailableException>(() => new MlKem768Kem().GenerateRecipient());
    }
}
