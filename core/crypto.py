"""
core/crypto.py — NullTrace payload encryption

All payloads are encrypted with AES-256-GCM before embedding.
Even if someone finds the carrier, they see random bytes without the key.
scrypt is used for key derivation — it's memory-hard, which makes
brute-force attacks expensive even with GPUs.

Payload wire format:
    VERSION(1) | SALT(32) | NONCE(12) | CIPHERTEXT+TAG(variable)
"""

import os
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

VERSION     = b'\x01'
SALT_LEN    = 32   # 256-bit salt — unique per operation
NONCE_LEN   = 12   # 96-bit nonce — NIST recommended for GCM
TAG_LEN     = 16   # 128-bit GCM authentication tag (appended by AESGCM automatically)
HEADER_LEN  = len(VERSION) + SALT_LEN + NONCE_LEN  # 45 bytes
MIN_PAYLOAD = HEADER_LEN + TAG_LEN                  # 61 bytes minimum


def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derive a 256-bit AES key from a password using scrypt.
    scrypt parameters: N=2^14 (16384), r=8, p=1 — ~64MB memory cost.
    This makes GPU brute-force attacks ~1000x harder than PBKDF2.
    """
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2 ** 14,
        r=8,
        p=1,
        backend=default_backend()
    )
    return kdf.derive(password.encode('utf-8'))


def encrypt(data: bytes, password: str) -> bytes:
    """
    Encrypt bytes using AES-256-GCM.
    Returns:  VERSION | SALT | NONCE | CIPHERTEXT | TAG
    Every call produces different ciphertext (random salt + nonce).
    The GCM authentication tag guarantees both secrecy and integrity —
    any tampering with the ciphertext causes decryption to fail.
    """
    salt  = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key   = derive_key(password, salt)
    aesgcm = AESGCM(key)
    # AESGCM.encrypt returns ciphertext + 16-byte auth tag concatenated
    ciphertext_and_tag = aesgcm.encrypt(nonce, data, None)
    return VERSION + salt + nonce + ciphertext_and_tag


def decrypt(data: bytes, password: str) -> bytes:
    """
    Decrypt an AES-256-GCM payload.
    Raises ValueError on wrong password, corrupted data, or auth tag mismatch.
    The GCM auth tag means there is NO partial decryption — wrong key = hard fail.
    """
    if len(data) < MIN_PAYLOAD:
        raise ValueError("Data too short to be a valid NullTrace payload.")

    version = data[0:1]
    if version != VERSION:
        raise ValueError(f"Unknown payload version: {version.hex()}")

    offset = 1
    salt   = data[offset : offset + SALT_LEN];  offset += SALT_LEN
    nonce  = data[offset : offset + NONCE_LEN]; offset += NONCE_LEN
    ciphertext_and_tag = data[offset:]

    key = derive_key(password, salt)
    aesgcm = AESGCM(key)

    try:
        return aesgcm.decrypt(nonce, ciphertext_and_tag, None)
    except Exception:
        raise ValueError("Decryption failed — wrong password or payload corrupted.")
