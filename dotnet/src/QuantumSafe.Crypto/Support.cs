using System.Buffers.Binary;
using System.Security.Cryptography;

namespace QuantumSafe.Crypto;

/// <summary>Runtime capability checks. On Linux .NET 10 needs OpenSSL 3.5+; on Windows, a PQC-capable CNG.</summary>
public static class PqcSupport
{
    public static bool MlKemAvailable => MLKem.IsSupported;

    public static bool MlDsaAvailable => MLDsa.IsSupported;

    internal static void EnsureMlKem()
    {
        if (!MLKem.IsSupported)
        {
            throw new PostQuantumUnavailableException("ML-KEM is not supported on this platform (needs OpenSSL 3.5+ or Windows CNG with PQC).");
        }
    }

    internal static void EnsureMlDsa()
    {
        if (!MLDsa.IsSupported)
        {
            throw new PostQuantumUnavailableException("ML-DSA is not supported on this platform (needs OpenSSL 3.5+ or Windows CNG with PQC).");
        }
    }
}

public sealed class PostQuantumUnavailableException : CryptographicException
{
    public PostQuantumUnavailableException()
    {
    }

    public PostQuantumUnavailableException(string message)
        : base(message)
    {
    }

    public PostQuantumUnavailableException(string message, Exception inner)
        : base(message, inner)
    {
    }
}

/// <summary>Unambiguous length-prefixed encoding, so concatenated fields cannot be shifted into each other.</summary>
internal static class WireFormat
{
    public static byte[] Concat(params byte[][] parts)
    {
        var total = parts.Sum(p => p.Length);
        var result = new byte[total];
        var offset = 0;
        foreach (var p in parts)
        {
            p.CopyTo(result, offset);
            offset += p.Length;
        }

        return result;
    }

    public static byte[] Join(params byte[][] parts)
    {
        var result = new byte[parts.Sum(p => p.Length + 4)];
        var offset = 0;
        foreach (var p in parts)
        {
            BinaryPrimitives.WriteInt32BigEndian(result.AsSpan(offset), p.Length);
            p.CopyTo(result, offset + 4);
            offset += p.Length + 4;
        }

        return result;
    }

    public static byte[][] Split(byte[] data, int expectedParts)
    {
        ArgumentNullException.ThrowIfNull(data);
        var parts = new List<byte[]>(expectedParts);
        var offset = 0;
        while (offset < data.Length)
        {
            if (data.Length - offset < 4)
            {
                throw new CryptographicException("Malformed encoding: truncated length prefix.");
            }

            var len = BinaryPrimitives.ReadInt32BigEndian(data.AsSpan(offset));
            if (len < 0 || len > data.Length - offset - 4)
            {
                throw new CryptographicException("Malformed encoding: invalid length.");
            }

            parts.Add(data.AsSpan(offset + 4, len).ToArray());
            offset += 4 + len;
        }

        if (parts.Count != expectedParts)
        {
            throw new CryptographicException($"Malformed encoding: expected {expectedParts} parts, found {parts.Count}.");
        }

        return [.. parts];
    }
}
