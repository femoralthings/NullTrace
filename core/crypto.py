"""
core/crypto.py — NullTrace payload encryption

All payloads are encrypted with AES-256-GCM before embedding.
Even if someone finds the carrier, they see random bytes without the key.
scrypt is used for key derivation — it's memory-hard, which makes
brute-force attacks expensive even with GPUs.

Payload wire format:
    VERSION(1) | SALT(32) | NONCE(12) | CIPHERTEXT+TAG(variable)

Key file support:
    If a key file is provided, its SHA-256 digest is mixed with the password
    before scrypt. This creates a two-factor key: password + physical file.
    Without both, decryption is impossible.
"""

import os
import hashlib
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

VERSION     = b'\x01'
SALT_LEN    = 32   # 256-bit salt — unique per operation
NONCE_LEN   = 12   # 96-bit nonce — NIST recommended for GCM
TAG_LEN     = 16   # 128-bit GCM authentication tag (appended by AESGCM automatically)
HEADER_LEN  = len(VERSION) + SALT_LEN + NONCE_LEN  # 45 bytes
MIN_PAYLOAD = HEADER_LEN + TAG_LEN                  # 61 bytes minimum


def _build_key_material(password: str, keyfile: bytes | None) -> bytes:
    """
    Combine password and optional key file into scrypt input bytes.
    If a key file is supplied, its SHA-256 digest is appended to the
    UTF-8 password bytes — requiring both factors for decryption.
    """
    pw_bytes = password.encode('utf-8')
    if keyfile is not None:
        kf_digest = hashlib.sha256(keyfile).digest()
        return pw_bytes + kf_digest
    return pw_bytes


def derive_key(password: str, salt: bytes,
               keyfile: bytes | None = None) -> bytes:
    """
    Derive a 256-bit AES key from a password (+ optional key file) using scrypt.
    scrypt parameters: N=2^14 (16384), r=8, p=1 — ~64MB memory cost.
    This makes GPU brute-force attacks ~1000x harder than PBKDF2.
    """
    key_material = _build_key_material(password, keyfile)
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2 ** 14,
        r=8,
        p=1,
        backend=default_backend()
    )
    return kdf.derive(key_material)


def encrypt(data: bytes, password: str,
            keyfile: bytes | None = None) -> bytes:
    """
    Encrypt bytes using AES-256-GCM.
    Returns:  VERSION | SALT | NONCE | CIPHERTEXT | TAG
    Every call produces different ciphertext (random salt + nonce).
    The GCM authentication tag guarantees both secrecy and integrity —
    any tampering with the ciphertext causes decryption to fail.

    keyfile: raw bytes of an optional key file. If provided, decryption
             requires the same file in addition to the password.
    """
    salt  = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key   = derive_key(password, salt, keyfile)
    aesgcm = AESGCM(key)
    # AESGCM.encrypt returns ciphertext + 16-byte auth tag concatenated
    ciphertext_and_tag = aesgcm.encrypt(nonce, data, None)
    return VERSION + salt + nonce + ciphertext_and_tag


def decrypt(data: bytes, password: str,
            keyfile: bytes | None = None) -> bytes:
    """
    Decrypt an AES-256-GCM payload.
    Raises ValueError on wrong password, corrupted data, or auth tag mismatch.
    The GCM auth tag means there is NO partial decryption — wrong key = hard fail.

    keyfile: must match the file used during encryption (if any).
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

    key = derive_key(password, salt, keyfile)
    aesgcm = AESGCM(key)

    try:
        return aesgcm.decrypt(nonce, ciphertext_and_tag, None)
    except Exception:
        raise ValueError("Decryption failed — wrong password/keyfile or payload corrupted.")
