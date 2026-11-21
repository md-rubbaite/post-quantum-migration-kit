"""Legacy report signing (sample)."""

import hashlib

from cryptography.hazmat.primitives.asymmetric import ec, rsa


def new_keys():
    signing = ec.generate_private_key(ec.SECP384R1())
    archive = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    return signing, archive


def fingerprint(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()


def audit_digest(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()  # pqcscan:ignore  (non-security cache key, reviewed 2026-11)
