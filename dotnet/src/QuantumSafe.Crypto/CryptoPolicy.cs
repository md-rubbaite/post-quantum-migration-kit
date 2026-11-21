namespace QuantumSafe.Crypto;

public enum KeyEstablishmentMode
{
    Classical,
    Hybrid,
    PostQuantumOnly,
}

/// <summary>What the policy decided, and whether that is weaker than what was asked for.</summary>
public sealed record PolicyDecision(KeyEstablishmentMode Mode, bool Downgraded, string Reason)
{
    public IKemScheme CreateScheme() => Mode switch
    {
        KeyEstablishmentMode.Classical => new EcdhP256Kem(),
        KeyEstablishmentMode.Hybrid => new HybridKem(),
        KeyEstablishmentMode.PostQuantumOnly => new MlKem768Kem(),
        _ => throw new InvalidOperationException($"Unknown mode {Mode}."),
    };
}

/// <summary>
/// Crypto-agility in one place: configuration chooses the algorithm, code never hard-codes it.
/// With <see cref="RequirePostQuantum"/> the policy fails closed instead of silently downgrading.
/// </summary>
public sealed record CryptoPolicy(KeyEstablishmentMode Preferred = KeyEstablishmentMode.Hybrid, bool RequirePostQuantum = false)
{
    public PolicyDecision Resolve(bool postQuantumAvailable)
    {
        if (Preferred == KeyEstablishmentMode.Classical)
        {
            return RequirePostQuantum
                ? throw new InvalidOperationException("Policy requires post-quantum key establishment but prefers Classical.")
                : new PolicyDecision(KeyEstablishmentMode.Classical, false, "Classical requested.");
        }

        if (postQuantumAvailable)
        {
            return new PolicyDecision(Preferred, false, $"{Preferred} available.");
        }

        if (RequirePostQuantum)
        {
            throw new PostQuantumUnavailableException($"Policy requires {Preferred}, but ML-KEM is not available on this platform.");
        }

        return new PolicyDecision(KeyEstablishmentMode.Classical, true, $"{Preferred} unavailable; downgraded to Classical. Record and alert on this.");
    }

    public PolicyDecision Resolve() => Resolve(PqcSupport.MlKemAvailable);
}
