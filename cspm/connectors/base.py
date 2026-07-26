"""Connector contract for Module 6.1.

A connector takes provider credentials, runs the cheapest possible read-only
API call to prove least-privilege access works, and produces the encrypted
column values to persist on ``cspm_cloud_accounts``. Raw secrets never leave
the request lifecycle (fetch → validate → encrypt → discard).
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field


class ConnectorError(Exception):
    """Raised when a credential validation call fails."""


@dataclass
class ValidationResult:
    ok: bool
    account_identifier: str = ""
    detail: str = ""
    # Column name -> value to persist on cspm_cloud_accounts (secrets encrypted).
    stored_fields: dict[str, str] = field(default_factory=dict)


class BaseConnector(abc.ABC):
    provider: str

    @abc.abstractmethod
    def validate(self) -> ValidationResult:
        """Run a minimal read-only call; return persistable (encrypted) fields."""


def get_connector(provider: str, **kwargs) -> BaseConnector:
    from cspm.connectors.aws import AWSConnector
    from cspm.connectors.azure import AzureConnector
    from cspm.connectors.gcp import GCPConnector

    mapping = {"aws": AWSConnector, "gcp": GCPConnector, "azure": AzureConnector}
    if provider not in mapping:
        raise ConnectorError(f"Unsupported provider: {provider}")
    return mapping[provider](**kwargs)
