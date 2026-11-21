"""Detection rules for quantum-vulnerable and classically weak cryptography.

Each rule maps a source-code or configuration pattern to an algorithm, a usage category and a
migration target. Categories follow NIST IR 8547 (final, October 2026): every quantum-vulnerable
public-key algorithm used for key establishment or digital signatures is deprecated after 2030
and disallowed after 2035, whatever the key size.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

KEY_ESTABLISHMENT = "key-establishment"
SIGNATURE = "signature"
CLASSICAL_WEAK = "classically-weak"
PQC = "post-quantum"
PROTOCOL = "protocol"


@dataclass(frozen=True)
class Rule:
    id: str
    algorithm: str
    category: str
    pattern: re.Pattern[str]
    replacement: str
    languages: tuple[str, ...] = ()  # empty = any file type

    @property
    def quantum_vulnerable(self) -> bool:
        return self.category in (KEY_ESTABLISHMENT, SIGNATURE, PROTOCOL)


def _r(pattern: str, flags: int = 0) -> re.Pattern[str]:
    return re.compile(pattern, flags)


KEM_TARGET = "ML-KEM-768 (FIPS 203), deployed as a hybrid with ECDH/X25519 during transition"
SIG_TARGET = "ML-DSA-65 (FIPS 204), or SLH-DSA (FIPS 205) for long-lived roots; composite during transition"
CODE = ("cs", "java", "py", "js", "ts", "go", "kt", "rb", "php")

RULES: tuple[Rule, ...] = (
    # ---- RSA (used for both encryption/key transport and signatures)
    Rule(
        "PQC001",
        "RSA",
        KEY_ESTABLISHMENT,
        _r(r"\bRSA(?:CryptoServiceProvider|\.Create|OAEP)\b|RSAEncryptionPadding|\.Encrypt\([^)]*RSAEncryptionPadding"),
        KEM_TARGET,
        ("cs",),
    ),
    Rule("PQC002", "RSA", SIGNATURE, _r(r"RSA\w*\.SignData|RSA\w*\.SignHash|RSASignaturePadding"), SIG_TARGET, ("cs",)),
    Rule(
        "PQC003",
        "RSA",
        KEY_ESTABLISHMENT,
        _r(r"KeyPairGenerator\.getInstance\(\s*\"RSA\"|Cipher\.getInstance\(\s*\"RSA"),
        KEM_TARGET,
        ("java", "kt"),
    ),
    Rule(
        "PQC004",
        "RSA",
        KEY_ESTABLISHMENT,
        _r(r"\brsa\.generate_private_key\b|\bRSA\.generate\(|\bpadding\.OAEP\b"),
        KEM_TARGET,
        ("py",),
    ),
    Rule(
        "PQC005",
        "RSA",
        KEY_ESTABLISHMENT,
        _r(r"generateKeyPair(?:Sync)?\(\s*['\"]rsa['\"]|publicEncrypt\("),
        KEM_TARGET,
        ("js", "ts"),
    ),
    Rule(
        "PQC006",
        "RSA",
        KEY_ESTABLISHMENT,
        _r(r"\brsa\.GenerateKey\(|\brsa\.EncryptOAEP\(|\brsa\.EncryptPKCS1v15\("),
        KEM_TARGET,
        ("go",),
    ),
    Rule(
        "PQC007",
        "RSA",
        SIGNATURE,
        _r(r"\brsa\.SignPKCS1v15\(|\brsa\.SignPSS\(|Signature\.getInstance\(\s*\"\w*withRSA"),
        SIG_TARGET,
        ("go", "java", "kt"),
    ),
    # ---- Elliptic curve and finite-field Diffie-Hellman
    Rule(
        "PQC010",
        "ECDH",
        KEY_ESTABLISHMENT,
        _r(
            r"\bECDiffieHellman\w*\b|KeyAgreement\.getInstance\(\s*\"ECDH|\bec\.ECDH\(\)|\becdh\.P(?:256|384|521)\(\)|"
            r"createECDH\("
        ),
        KEM_TARGET,
        CODE,
    ),
    Rule(
        "PQC011",
        "X25519",
        KEY_ESTABLISHMENT,
        _r(r"\bX25519(?:PrivateKey|PublicKey)?\b(?!MLKEM)|\becdh\.X25519\(\)|curve25519"),
        KEM_TARGET,
        CODE,
    ),
    Rule(
        "PQC012",
        "DH",
        KEY_ESTABLISHMENT,
        _r(
            r"\bDiffieHellman\b(?!\w)|\bdh\.generate_parameters\b|KeyAgreement\.getInstance\(\s*\"DH\"|createDiffieHellman\("
        ),
        KEM_TARGET,
        CODE,
    ),
    # ---- ECDSA / EdDSA / DSA
    Rule(
        "PQC020",
        "ECDSA",
        SIGNATURE,
        _r(
            r"\bECDsa\w*\b|Signature\.getInstance\(\s*\"\w*withECDSA|\bec\.ECDSA\(|\bec\.generate_private_key\b|"
            r"\becdsa\.(?:GenerateKey|Sign\w*)\("
        ),
        SIG_TARGET,
        CODE,
    ),
    Rule(
        "PQC021",
        "Ed25519",
        SIGNATURE,
        _r(r"\bEd25519(?:PrivateKey|PublicKey|Signer)?\b|\bed25519\.(?:GenerateKey|Sign)\(|['\"]ed25519['\"]"),
        SIG_TARGET,
        CODE,
    ),
    Rule(
        "PQC022",
        "DSA",
        SIGNATURE,
        _r(
            r"\bDSACryptoServiceProvider\b|\bDSA\.Create\b|KeyPairGenerator\.getInstance\(\s*\"DSA\"|\bdsa\.generate_private_key\b"
        ),
        SIG_TARGET,
        CODE,
    ),
    # ---- tokens, keys and certificates in configuration and key material
    Rule(
        "PQC030",
        "RSA/ECDSA (JWT)",
        SIGNATURE,
        _r(
            r"(?i)[\"']?alg(?:orithm)?[\"']?\s*[:=]\s*[\"']?(RS256|RS384|RS512|PS256|PS384|PS512|ES256|ES384|ES512|EdDSA)\b|"
            r"SecurityAlgorithms\.(?:RsaSha|EcdsaSha|RsaSsaPss)\w*"
        ),
        SIG_TARGET,
    ),
    Rule(
        "PQC031",
        "RSA (key file)",
        SIGNATURE,
        _r(r"-----BEGIN (?:RSA )?(?:PUBLIC|PRIVATE) KEY-----|^ssh-rsa AAAA", re.M),
        SIG_TARGET,
    ),
    Rule(
        "PQC032",
        "ECDSA/EdDSA (key file)",
        SIGNATURE,
        _r(r"-----BEGIN EC (?:PRIVATE|PUBLIC) KEY-----|^(?:ecdsa-sha2-nistp\d+|ssh-ed25519) AAAA", re.M),
        SIG_TARGET,
    ),
    Rule(
        "PQC033",
        "TLS key exchange",
        PROTOCOL,
        _r(
            r"(?i)\b(?:ECDHE|DHE)-(?:RSA|ECDSA)-[A-Z0-9-]+\b|\bTLS_(?:ECDHE|DHE|RSA)_WITH_\w+|"
            r"ssl_ecdh_curve\s+(?![^;]*MLKEM)[^;]*|(?:Curves|Groups|ecdh-curve)\s*[:=]\s*[\"']?(?:X25519|P-256|prime256v1|secp384r1)(?![\w:]*MLKEM)"
        ),
        "Enable hybrid groups such as X25519MLKEM768 (TLS 1.3); keep TLS 1.3 only",
    ),
    Rule(
        "PQC034",
        "Legacy TLS",
        CLASSICAL_WEAK,
        _r(r"(?i)\bTLSv1(?:\.[01])?\b(?!\.[23])|SslProtocols\.Tls(?:11)?\b(?!1[23])|\bSSLv3\b"),
        "TLS 1.3 only (TLS 1.2 minimum)",
    ),
    # ---- classically weak primitives (fix while touching the code)
    Rule(
        "PQC040",
        "MD5",
        CLASSICAL_WEAK,
        _r(r"\bMD5(?:CryptoServiceProvider|\.Create|\.HashData)?\b|hashlib\.md5\b|createHash\(\s*['\"]md5"),
        "SHA-256 or SHA-3",
    ),
    Rule(
        "PQC041",
        "SHA-1",
        CLASSICAL_WEAK,
        _r(
            r"\bSHA1(?:Managed|CryptoServiceProvider|\.Create|\.HashData)?\b|hashlib\.sha1\b|createHash\(\s*['\"]sha1|\"SHA-?1\""
        ),
        "SHA-256 or SHA-3",
    ),
    Rule(
        "PQC042",
        "DES/3DES",
        CLASSICAL_WEAK,
        _r(r"\b(?:TripleDES|DESede|DES)(?:CryptoServiceProvider|\.Create)?\b(?!\w)|\bdes-ede3"),
        "AES-256-GCM",
    ),
    Rule("PQC043", "RC4", CLASSICAL_WEAK, _r(r"(?i)\bRC4\b|\bARCFOUR\b"), "AES-256-GCM or ChaCha20-Poly1305"),
    # ---- already post-quantum (inventory only)
    Rule("PQC090", "ML-KEM", PQC, _r(r"\bMLKem\w*\b|\bML-KEM(?:-\d+)?\b|\bX25519MLKEM768\b|\bKyber\d*\b", re.I), "—"),
    Rule(
        "PQC091",
        "ML-DSA / SLH-DSA",
        PQC,
        _r(r"\bMLDsa\w*\b|\bSlhDsa\w*\b|\bML-DSA(?:-\d+)?\b|\bSLH-DSA\b|\bDilithium\d*\b", re.I),
        "—",
    ),
)

EXTENSIONS: dict[str, str] = {
    ".cs": "cs",
    ".java": "java",
    ".kt": "kt",
    ".py": "py",
    ".js": "js",
    ".mjs": "js",
    ".ts": "ts",
    ".go": "go",
    ".rb": "rb",
    ".php": "php",
    ".json": "config",
    ".yaml": "config",
    ".yml": "config",
    ".toml": "config",
    ".ini": "config",
    ".conf": "config",
    ".cfg": "config",
    ".config": "config",
    ".xml": "config",
    ".env": "config",
    ".pem": "key",
    ".pub": "key",
    ".key": "key",
    ".crt": "key",
    ".cer": "key",
}
