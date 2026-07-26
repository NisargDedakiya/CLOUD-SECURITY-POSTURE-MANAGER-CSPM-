"""Azure connector — service principal (client secret AES-256 encrypted)."""

from __future__ import annotations

from cspm.connectors.base import BaseConnector, ConnectorError, ValidationResult
from cspm.security.crypto import encrypt


class AzureConnector(BaseConnector):
    provider = "azure"

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        validator=None,
    ) -> None:
        if not all([tenant_id, client_id, client_secret]):
            raise ConnectorError("tenant_id, client_id and client_secret are required.")
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self._validator = validator

    def validate(self) -> ValidationResult:
        try:
            if self._validator is not None:
                self._validator(self.tenant_id, self.client_id, self.client_secret)
            else:  # pragma: no cover - requires azure-identity
                self._live_validate()
        except ConnectorError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise ConnectorError(f"Azure validation failed: {exc}") from exc

        return ValidationResult(
            ok=True,
            account_identifier=self.tenant_id,
            detail=f"Service principal {self.client_id}",
            stored_fields={
                "azure_tenant_id": self.tenant_id,
                "azure_client_id": self.client_id,
                "azure_secret_enc": encrypt(self.client_secret),
            },
        )

    def _live_validate(self) -> None:  # pragma: no cover
        from azure.identity import ClientSecretCredential

        cred = ClientSecretCredential(self.tenant_id, self.client_id, self.client_secret)
        cred.get_token("https://management.azure.com/.default")
