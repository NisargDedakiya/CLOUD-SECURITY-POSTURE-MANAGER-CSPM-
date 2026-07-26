"""AES-256-GCM field-level encryption for cloud credentials.

Cloud secrets (AWS secret keys, GCP service-account JSON, Azure client secrets)
are encrypted at rest with a 256-bit key and stored in dedicated ``*_enc``
columns. Ciphertext is base64url-encoded ``nonce || ciphertext || tag``.

Usage pattern (spec 6.1): fetch → decrypt → use → discard within the request
lifecycle. Never log or return plaintext secrets.
"""

from __future__ import annotations

import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from cspm.config import get_settings

_NONCE_BYTES = 12  # 96-bit nonce recommended for GCM

# Dev/test fallback key so the package works without configuration. Generated
# once per process; production MUST set CSPM_ENCRYPTION_KEY.
_DEV_KEY = base64.urlsafe_b64encode(os.urandom(32)).decode()


def _load_key() -> bytes:
    raw = get_settings().encryption_key or _DEV_KEY
    key = base64.urlsafe_b64decode(raw)
    if len(key) != 32:
        raise ValueError("CSPM_ENCRYPTION_KEY must decode to 32 bytes (AES-256).")
    return key


def generate_key() -> str:
    """Return a fresh base64url-encoded 256-bit key for CSPM_ENCRYPTION_KEY."""
    return base64.urlsafe_b64encode(os.urandom(32)).decode()


def encrypt(plaintext: str) -> str:
    """Encrypt a UTF-8 string, returning base64url ciphertext."""
    if plaintext is None:
        raise ValueError("Cannot encrypt None.")
    aes = AESGCM(_load_key())
    nonce = os.urandom(_NONCE_BYTES)
    ct = aes.encrypt(nonce, plaintext.encode("utf-8"), None)
    return base64.urlsafe_b64encode(nonce + ct).decode()


def decrypt(token: str) -> str:
    """Decrypt base64url ciphertext produced by :func:`encrypt`."""
    blob = base64.urlsafe_b64decode(token)
    nonce, ct = blob[:_NONCE_BYTES], blob[_NONCE_BYTES:]
    aes = AESGCM(_load_key())
    return aes.decrypt(nonce, ct, None).decode("utf-8")
