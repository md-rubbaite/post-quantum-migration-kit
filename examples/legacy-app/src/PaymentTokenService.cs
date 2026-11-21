// Legacy service (sample). Encrypts card tokens for a partner with RSA and signs webhooks with ECDSA.
using System.Security.Cryptography;
using System.Text;

public sealed class PaymentTokenService
{
    private readonly RSA _partnerKey = RSA.Create(3072);
    private readonly ECDsa _webhookKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

    public byte[] EncryptForPartner(string token) =>
        _partnerKey.Encrypt(Encoding.UTF8.GetBytes(token), RSAEncryptionPadding.OaepSHA256);

    public byte[] SignWebhook(byte[] body) => _webhookKey.SignData(body, HashAlgorithmName.SHA256);

    public static byte[] LegacyChecksum(byte[] data) => MD5.HashData(data);

    public static byte[] SessionKey(ECDiffieHellman local, ECDiffieHellmanPublicKey remote) =>
        local.DeriveKeyMaterial(remote);
}
