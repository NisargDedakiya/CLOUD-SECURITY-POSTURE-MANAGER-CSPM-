"""Pluggable key providers for envelope encryption + rotation.

A provider issues short-lived AES-256 *data keys* and can later unwrap them. The
root key never leaves the provider (KMS/Vault), which is the key-management
property MNC security teams require.

- ``env``     : a single static root key from CSPM_ENCRYPTION_KEY (dev/simple).
- ``aws_kms`` : ``GenerateDataKey`` / ``Decrypt`` against a KMS CMK (rotation via KMS).
- ``vault``   : HashiCorp Vault Transit ``datakey``/``decrypt`` endpoints.

``wrap_new_key`` → (key_ref, plaintext_data_key, wrapped_key)
``unwrap_key(key_ref, wrapped_key)`` → plaintext_data_key
"""

from __future__ import annotations

import abc
import base64
import functools
import os

from cspm.config import get_settings


class KeyProviderError(RuntimeError):
    pass


class KeyProvider(abc.ABC):
    @abc.abstractmethod
    def wrap_new_key(self) -> tuple[str, bytes, bytes]: ...

    @abc.abstractmethod
    def unwrap_key(self, key_ref: str, wrapped: bytes) -> bytes: ...


# Dev fallback key so the package works without configuration.
_DEV_KEY = base64.urlsafe_b64encode(os.urandom(32)).decode()


class EnvKeyProvider(KeyProvider):
    """Static root key from the environment. Rotation = re-key + re-encrypt."""

    def __init__(self) -> None:
        raw = get_settings().encryption_key or _DEV_KEY
        self._key = base64.urlsafe_b64decode(raw)
        if len(self._key) != 32:
            raise KeyProviderError("CSPM_ENCRYPTION_KEY must decode to 32 bytes.")

    def wrap_new_key(self) -> tuple[str, bytes, bytes]:
        # The data key IS the root key; nothing to wrap.
        return ("env", self._key, b"")

    def unwrap_key(self, key_ref: str, wrapped: bytes) -> bytes:
        return self._key


class AwsKmsKeyProvider(KeyProvider):  # pragma: no cover - requires AWS KMS
    def __init__(self) -> None:
        self.key_id = get_settings().kms_key_id
        if not self.key_id:
            raise KeyProviderError("CSPM_KMS_KEY_ID required for aws_kms provider.")

    def _client(self):
        import boto3

        return boto3.client("kms")

    def wrap_new_key(self) -> tuple[str, bytes, bytes]:
        resp = self._client().generate_data_key(KeyId=self.key_id, KeySpec="AES_256")
        return (self.key_id, resp["Plaintext"], resp["CiphertextBlob"])

    def unwrap_key(self, key_ref: str, wrapped: bytes) -> bytes:
        return self._client().decrypt(CiphertextBlob=wrapped, KeyId=key_ref)["Plaintext"]


class VaultKeyProvider(KeyProvider):  # pragma: no cover - requires Vault
    def __init__(self) -> None:
        s = get_settings()
        if not (s.vault_addr and s.vault_key_path):
            raise KeyProviderError("CSPM_VAULT_ADDR and CSPM_VAULT_KEY_PATH required.")
        self.addr = s.vault_addr.rstrip("/")
        self.key_name = s.vault_key_path
        self.token = os.getenv("VAULT_TOKEN", "")

    def _req(self, path: str, payload: dict) -> dict:
        import requests

        r = requests.post(
            f"{self.addr}/v1/transit/{path}",
            json=payload,
            headers={"X-Vault-Token": self.token},
            timeout=10,
        )
        r.raise_for_status()
        return r.json()["data"]

    def wrap_new_key(self) -> tuple[str, bytes, bytes]:
        data = self._req(f"datakey/plaintext/{self.key_name}", {})
        return (self.key_name, base64.b64decode(data["plaintext"]), data["ciphertext"].encode())

    def unwrap_key(self, key_ref: str, wrapped: bytes) -> bytes:
        data = self._req(f"decrypt/{key_ref}", {"ciphertext": wrapped.decode()})
        return base64.b64decode(data["plaintext"])


@functools.lru_cache
def get_key_provider() -> KeyProvider:
    provider = get_settings().key_provider
    if provider == "aws_kms":
        return AwsKmsKeyProvider()
    if provider == "vault":
        return VaultKeyProvider()
    return EnvKeyProvider()
