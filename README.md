# post-quantum-migration-kit

[![ci](https://github.com/md-rubbaite/post-quantum-migration-kit/actions/workflows/ci.yml/badge.svg)](https://github.com/md-rubbaite/post-quantum-migration-kit/actions/workflows/ci.yml)
![python](https://img.shields.io/badge/scanner-python%203.11%E2%80%933.13-blue)
![dotnet](https://img.shields.io/badge/.NET-10-512BD4)
![standards](https://img.shields.io/badge/NIST-FIPS%20203%20%C2%B7%20204%20%C2%B7%20IR%208547-0F766E)
![license](https://img.shields.io/badge/license-MIT-green)

**Find the cryptography that quantum computers will break, decide what to fix first, and move to
post-quantum algorithms without a big-bang rewrite.**

## The problem

RSA, ECDSA, EdDSA, ECDH and Diffie-Hellman protect almost every login, payment, API call and backup.
A large enough quantum computer breaks all of them. Two facts make this a project for now, not later:

- **Harvest now, decrypt later.** Traffic and backups recorded today can be decrypted in the future.
  Data that must stay secret for ten years is already at risk if its key exchange is classical.
- **The dates are set.** NIST IR 8547 (final, October 2026) deprecates these algorithms after **2030**
  and disallows them after **2035**, at every key size.

Most organisations cannot answer the first question: *where do we even use this?*

## What is in the kit

| Part | What it does |
|---|---|
| [`scanner/`](scanner) — **pqcscan** | Scans code (C#, Java/Kotlin, Python, JS/TS, Go) and config (JSON, YAML, nginx, keys) for 24 crypto patterns; builds an inventory; ranks findings by harvest-now-decrypt-later risk; outputs text, JSON, Markdown and SARIF for GitHub code scanning |
| [`dotnet/`](dotnet) — **QuantumSafe.Crypto** | .NET 10 reference: ECDH, ML-KEM-768 and a hybrid ECDH + ML-KEM KEM behind one interface; AES-256-GCM envelopes with downgrade protection; ECDSA and ML-DSA-65 signers; a policy that chooses the algorithm and refuses silent downgrades |
| [`docs/migration-playbook.md`](docs/migration-playbook.md) | Algorithm mapping, phases from inventory to retirement, size limits and operational checks |
| [`docs/adr/0001`](docs/adr/0001-hybrid-key-establishment-with-policy.md) | Why hybrid, how the combiner binds both halves, and the trade-offs |

## 1. Inventory and prioritise with pqcscan

```bash
pip install ./scanner
pqcscan examples/legacy-app --config examples/pqcscan.toml
```

```text
critical PQC033  TLS key exchange        config/nginx.conf:4
critical PQC001  RSA                     src/PaymentTokenService.cs:7
critical PQC010  ECDH                    src/PaymentTokenService.cs:17
critical PQC004  RSA                     src/report_signer.py:10
critical PQC011  X25519                  src/session.go:10
medium   PQC030  RSA/ECDSA (JWT)         config/appsettings.json:4
medium   PQC020  ECDSA                   src/PaymentTokenService.cs:8
medium   PQC040  MD5                     src/PaymentTokenService.cs:15
info     PQC090  ML-KEM                  src/HybridClient.java:3
…
15 findings, 11 quantum-vulnerable in 6 files, 1 post-quantum usages
```

**How priority is set.** Key establishment is *critical* when data shelf life plus migration time
reaches past the planning horizon (2035), following Mosca's inequality; otherwise *high*. Signatures are
*high* when the migration cannot finish before 2030 deprecation, otherwise *medium*. Classically weak
primitives (MD5, SHA-1, 3DES, RC4, old TLS) are *medium*. Post-quantum usage is recorded as *info*, so
the inventory also shows progress.

```toml
# pqcscan.toml
[pqcscan]
data_shelf_life_years = 10
migration_years = 3
exclude = ["**/vendor/**"]
```

Other formats: `--format json` (inventory with policy and summary), `--format markdown`,
`--format sarif` (upload to GitHub code scanning). Use `--fail-on critical` as a CI gate and
`# pqcscan:ignore` on a reviewed line.

## 2. Migrate with crypto-agility in .NET 10

```csharp
var decision = new CryptoPolicy(KeyEstablishmentMode.Hybrid, RequirePostQuantum: true).Resolve();
IKemScheme scheme = decision.CreateScheme();          // HybridKem: ECDH P-256 + ML-KEM-768

using var recipient = scheme.GenerateRecipient();
byte[] envelope = Envelope.Seal(scheme, recipient.PublicKey, plaintext, associatedData);
byte[] opened   = Envelope.Open(recipient, envelope, associatedData);
```

- **Hybrid:** the session key comes from both ECDH and ML-KEM through HKDF-SHA256, with both
  encapsulations and both public keys in the context. It stays secure if either algorithm holds.
- **No silent downgrade:** if ML-KEM is unavailable the decision is marked `Downgraded`; with
  `RequirePostQuantum` it throws instead.
- **Authenticated header:** the envelope's version and algorithm id are part of the AES-GCM associated
  data, so editing them to force a weaker algorithm makes decryption fail.
- **Signatures:** `Signers.Create(SignatureAlgorithm.MlDsa65)` or `EcdsaP256`, chosen by configuration.

Platform note: .NET 10 uses the operating system's implementation. On Linux that needs OpenSSL 3.5 or
newer; on Windows, a build with PQC in CNG. Check `PqcSupport.MlKemAvailable` at start-up.

```bash
dotnet run --project dotnet/samples/HybridDemo -- --require-pqc
```

## Tests and CI

| Job | What runs |
|---|---|
| scanner | 42 tests on Python 3.11, 3.12, 3.13 (every rule, false-positive checks, priorities, suppression, exclusions, SARIF shape, CLI) plus ruff |
| inventory | Scans the sample app and publishes the Markdown, JSON and SARIF inventory as an artifact and job summary |
| dotnet (Windows) | All tests with `REQUIRE_PQC=true`: ML-KEM and ML-DSA must really run (key and ciphertext sizes checked against FIPS 203/204) |
| dotnet (Linux) | All classical, envelope, policy and encoding tests; PQC tests run where the runner's OpenSSL supports them |

## Scope and limits

Pattern-based scanning finds most direct uses but not cryptography hidden inside third-party binaries,
HSMs, cloud services or partner connections; list those by hand in the inventory. The .NET library is a
reference design for the migration pattern, not a replacement for a reviewed protocol such as TLS 1.3
with hybrid groups. Nothing here claims FIPS validation.

## References

- NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA), August 2024
- NIST IR 8547, *Transition to Post-Quantum Cryptography Standards* (final, October 2026)
- Microsoft, *Post-Quantum Cryptography in .NET* (November 2025)

---

Author: [Rubbaite T. Hassain](https://tanvir.info.bd) ([LinkedIn](https://www.linkedin.com/in/rubbaite)) · Software Architect, Founder of [Datazo InfoTech](https://www.datazoinfotech.com.bd) · MIT License

Architecture, requirements and review by Rubbaite T. Hassain; implementation AI-assisted.
