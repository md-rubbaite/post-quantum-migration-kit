# Post-quantum migration playbook

A practical sequence for moving an application estate off quantum-vulnerable public-key cryptography.
It follows the timeline in NIST IR 8547 (final, October 2026) and the NIST post-quantum standards
FIPS 203, 204 and 205 (August 2024).

## Why now

- **Harvest now, decrypt later.** Encrypted traffic and backups captured today can be decrypted once a
  cryptographically relevant quantum computer exists. Anything that must stay confidential for years is
  already exposed if its key exchange is RSA, ECDH or DH.
- **Fixed dates.** Under NIST IR 8547, quantum-vulnerable public-key algorithms (RSA, ECDSA, EdDSA, ECDH,
  DH) are deprecated after 2030 and disallowed after 2035, whatever the key size.
- **Long lead times.** Earlier cryptographic transitions took 10 to 20 years. Libraries, HSMs, certificates,
  partners and devices all have to move.

Symmetric cryptography and hashes (AES-256, SHA-256/384, SHA-3) remain fine; the work is in public-key
cryptography.

## Algorithm mapping

| Today | Used for | Move to | Notes |
|---|---|---|---|
| RSA-OAEP, ECDH, X25519, DH | Key establishment | **ML-KEM-768** (FIPS 203) | Deploy as a hybrid with ECDH/X25519 first |
| ECDHE in TLS | Session keys | **X25519MLKEM768** hybrid group, TLS 1.3 | Often a library/config upgrade, no code change |
| RSA, ECDSA, Ed25519 signatures | Tokens, code signing, documents | **ML-DSA-65** (FIPS 204) | Larger keys and signatures; check token and header size limits |
| Long-lived roots, firmware | Signatures that must last decades | **SLH-DSA** (FIPS 205) | Hash-based, conservative, large signatures |
| MD5, SHA-1, 3DES, RC4, TLS < 1.2 | Anything | SHA-256/SHA-3, AES-256-GCM, TLS 1.3 | Not a quantum issue, but fix while touching the code |

## Phases

1. **Inventory.** Run `pqcscan` over every repository and configuration store. Add certificates, HSM
   keys, SSH keys, VPNs and third-party services that the scanner cannot see. Output: a cryptographic
   bill of materials (the JSON report) owned by a named team.
2. **Prioritise.** Set `data_shelf_life_years` and `migration_years` per system. If shelf life plus
   migration time reaches past the planning horizon (Mosca's inequality), key establishment is
   *critical* now. Signatures matter most for long-lived trust anchors and anything still in use after 2030.
3. **Make it agile.** Put algorithm choice behind one interface and configuration (see
   `QuantumSafe.Crypto.CryptoPolicy`). Version every ciphertext and signature format so old and new
   can coexist. Authenticate the algorithm identifier so it cannot be downgraded.
4. **Go hybrid.** Combine ECDH and ML-KEM so security holds if either survives. Turn on hybrid TLS groups
   where the stack supports them. Measure handshake size and latency.
5. **Migrate signatures.** Start with internal tokens and code signing, then certificates as CAs and
   clients support ML-DSA or composite certificates.
6. **Retire.** Remove classical-only paths before 2030 for deprecated uses; make sure nothing depends on
   them after 2035. Keep the scanner in CI with `--fail-on` so regressions are caught.

## Operational checks

- Platform support: .NET 10 needs OpenSSL 3.5 or newer on Linux, or a Windows build with PQC in CNG.
  Check `MLKem.IsSupported` at start-up and decide explicitly whether to downgrade or fail closed.
- Size limits: ML-KEM-768 public keys are 1,184 bytes and ciphertexts 1,088 bytes; ML-DSA-65 signatures
  are 3,309 bytes. JWTs, cookies, headers, database columns and MTU-sensitive protocols may need changes.
- HSMs and KMS: confirm the vendor's roadmap and firmware versions for ML-KEM and ML-DSA.
- Partners: agree on hybrid groups and certificate formats before cut-over.
