"""GCP connector — service-account JSON key (AES-256 encrypted at rest)."""

from __future__ import annotations

import json

from cspm.connectors.base import BaseConnector, ConnectorError, ValidationResult
from cspm.security.crypto import encrypt


class GCPConnector(BaseConnector):
    provider = "gcp"

    def __init__(self, service_account_json: str, validator=None) -> None:
        if not service_account_json:
            raise ConnectorError("service_account_json is required for GCP.")
        self.service_account_json = service_account_json
        # Injectable validator for testing without google-auth/creds.
        self._validator = validator

    def validate(self) -> ValidationResult:
        try:
            info = json.loads(self.service_account_json)
        except json.JSONDecodeError as exc:
            raise ConnectorError("service_account_json is not valid JSON.") from exc
        if "client_email" not in info or "project_id" not in info:
            raise ConnectorError("service account JSON missing client_email/project_id.")

        try:
            if self._validator is not None:
                self._validator(info)
            else:  # pragma: no cover - requires google-auth
                self._live_validate(info)
        except ConnectorError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise ConnectorError(f"GCP validation failed: {exc}") from exc

        return ValidationResult(
            ok=True,
            account_identifier=info["project_id"],
            detail=f"Service account {info['client_email']}",
            stored_fields={"gcp_sa_key_enc": encrypt(self.service_account_json)},
        )

    def _live_validate(self, info: dict) -> None:  # pragma: no cover
        from google.oauth2 import service_account  # noqa: F401

        service_account.Credentials.from_service_account_info(info)
