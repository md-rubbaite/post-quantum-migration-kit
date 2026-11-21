using System.Security.Cryptography;

namespace QuantumSafe.Crypto;

public enum SignatureAlgorithm
{
    EcdsaP256,
    MlDsa65,
}

/// <summary>A signing key behind one interface, so the algorithm can be swapped by configuration.</summary>
public interface ISigner : IDisposable
{
    SignatureAlgorithm Algorithm { get; }

    byte[] PublicKey { get; }

    byte[] Sign(byte[] data);
}

public static class Signers
{
    public static ISigner Create(SignatureAlgorithm algorithm) => algorithm switch
    {
        SignatureAlgorithm.EcdsaP256 => new EcdsaSigner(),
        SignatureAlgorithm.MlDsa65 => new MlDsaSigner(),
        _ => throw new ArgumentOutOfRangeException(nameof(algorithm)),
    };

    public static bool Verify(SignatureAlgorithm algorithm, byte[] publicKey, byte[] data, byte[] signature)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(signature);
        switch (algorithm)
        {
            case SignatureAlgorithm.EcdsaP256:
            {
                using var ecdsa = ECDsa.Create();
                ecdsa.ImportSubjectPublicKeyInfo(publicKey, out _);
                return ecdsa.VerifyData(data, signature, HashAlgorithmName.SHA256);
            }

            case SignatureAlgorithm.MlDsa65:
            {
                PqcSupport.EnsureMlDsa();
                using var key = MLDsa.ImportMLDsaPublicKey(MLDsaAlgorithm.MLDsa65, publicKey);
                return key.VerifyData(data.AsSpan(), signature.AsSpan());
            }

            default:
                throw new ArgumentOutOfRangeException(nameof(algorithm));
        }
    }

    private sealed class EcdsaSigner : ISigner
    {
        private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        public SignatureAlgorithm Algorithm => SignatureAlgorithm.EcdsaP256;

        public byte[] PublicKey => _key.ExportSubjectPublicKeyInfo();

        public byte[] Sign(byte[] data) => _key.SignData(data, HashAlgorithmName.SHA256);

        public void Dispose() => _key.Dispose();
    }

    /// <summary>ML-DSA-65 (NIST FIPS 204).</summary>
    private sealed class MlDsaSigner : ISigner
    {
        private readonly MLDsa _key;

        public MlDsaSigner()
        {
            PqcSupport.EnsureMlDsa();
            _key = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
        }

        public SignatureAlgorithm Algorithm => SignatureAlgorithm.MlDsa65;

        public byte[] PublicKey
        {
            get
            {
                var pk = new byte[MLDsaAlgorithm.MLDsa65.PublicKeySizeInBytes];
                _key.ExportMLDsaPublicKey(pk.AsSpan());
                return pk;
            }
        }

        public byte[] Sign(byte[] data)
        {
            ArgumentNullException.ThrowIfNull(data);
            var signature = new byte[MLDsaAlgorithm.MLDsa65.SignatureSizeInBytes];
            _key.SignData(data.AsSpan(), signature.AsSpan());
            return signature;
        }

        public void Dispose() => _key.Dispose();
    }
}
