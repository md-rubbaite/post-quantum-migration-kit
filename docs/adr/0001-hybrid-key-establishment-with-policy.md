# ADR 0001: Hybrid key establishment behind a crypto-agility policy

- **Status:** Accepted
- **Date:** 2026-11-22

## Context

Systems that protect long-lived data (payments, health records, legal archives) are exposed to
harvest-now-decrypt-later today. NIST IR 8547 deprecates RSA, ECC and DH after 2030 and disallows them
after 2035. ML-KEM (FIPS 203) is standardised and available in .NET 10, but platform support still
varies (OpenSSL 3.5+ on Linux, recent Windows builds), and implementations are young.

## Decision

1. **Hybrid by default.** Derive session keys from ECDH P-256 *and* ML-KEM-768. The combiner is
   HKDF-SHA256 over both shared secrets, with both encapsulations and both public keys in the context,
   so neither half can be replaced or replayed on its own. Security holds if either algorithm holds.
2. **One policy object decides.** `CryptoPolicy` chooses Classical, Hybrid or PostQuantumOnly from
   configuration and platform support. Application code depends on `IKemScheme`, never on an algorithm.
3. **No silent downgrade.** When ML-KEM is unavailable the decision says `Downgraded = true` so it can be
   logged and alerted on; with `RequirePostQuantum` the policy fails closed instead.
4. **Versioned, authenticated format.** Envelopes carry a version and an algorithm identifier that are
   bound into the AES-GCM associated data, so changing the header to force a weaker algorithm fails.
5. **Signatures through `ISigner`.** ECDSA today, ML-DSA-65 where available; the choice is configuration.

## Consequences

- Positive: protects data recorded today; algorithm changes become configuration changes; downgrade is
  visible or impossible.
- Negative: larger keys and messages (about 1.2 KB extra per public key and per encapsulation); two
  algorithms to operate during the transition; tests that need PQC depend on the runner's platform
  (CI requires them on Windows and runs them on Linux only where OpenSSL supports them).
- Follow-up: X25519 for the classical half where the platform exposes it; composite ML-DSA certificates
  once CA support is available.
