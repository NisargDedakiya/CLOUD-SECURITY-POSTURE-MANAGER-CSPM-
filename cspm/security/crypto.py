"""AES-256-GCM field-level encryption with envelope keys + rotation.

Ciphertext layout (base64url), version 2:
    b"\\x02" | ref_len(1) | key_ref | wrapped_len(2 BE) | wrapped_key | nonce(12) | ct

The data key that encrypts the field is itself wrapped by a KMS/Vault root key
(see :mod:`cspm.security.keyprovider`), so rotating the root key does not require
re-encrypting every row. Legacy v1 ciphertext (nonce||ct under the env key) is
still decryptable for backward compatibility.

Usage (spec 6.1): fetch → decrypt → use → discard within the request lifecycle.
Never log or return plaintext secrets.
"""

from __future__ import annotations

import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from cspm.security.keyprovider import EnvKeyProvider, get_key_provider

_NONCE_BYTES = 12
_VERSION = 2


def generate_key() -> str:
    """Return a fresh base64url-encoded 256-bit key for CSPM_ENCRYPTION_KEY."""
    return base64.urlsafe_b64encode(os.urandom(32)).decode()


def encrypt(plaintext: str) -> str:
    if plaintext is None:
        raise ValueError("Cannot encrypt None.")
    key_ref, data_key, wrapped = get_key_provider().wrap_new_key()
    nonce = os.urandom(_NONCE_BYTES)
    ct = AESGCM(data_key).encrypt(nonce, plaintext.encode("utf-8"), None)

    ref_b = key_ref.encode("utf-8")
    blob = (
        bytes([_VERSION, len(ref_b)])
        + ref_b
        + len(wrapped).to_bytes(2, "big")
        + wrapped
        + nonce
        + ct
    )
    return base64.urlsafe_b64encode(blob).decode()


def decrypt(token: str) -> str:
    blob = base64.urlsafe_b64decode(token)
    if not blob or blob[0] != _VERSION:
        return _decrypt_legacy(blob)

    i = 1
    ref_len = blob[i]
    i += 1
    key_ref = blob[i : i + ref_len].decode("utf-8")
    i += ref_len
    wrapped_len = int.from_bytes(blob[i : i + 2], "big")
    i += 2
    wrapped = blob[i : i + wrapped_len]
    i += wrapped_len
    nonce = blob[i : i + _NONCE_BYTES]
    ct = blob[i + _NONCE_BYTES :]

    data_key = get_key_provider().unwrap_key(key_ref, wrapped)
    return AESGCM(data_key).decrypt(nonce, ct, None).decode("utf-8")


def _decrypt_legacy(blob: bytes) -> str:
    """Decrypt v1 ciphertext: nonce||ct under the env root key."""
    key = EnvKeyProvider().wrap_new_key()[1]
    nonce, ct = blob[:_NONCE_BYTES], blob[_NONCE_BYTES:]
    return AESGCM(key).decrypt(nonce, ct, None).decode("utf-8")
