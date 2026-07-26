"""Azure provider (mock mode ships sample resources)."""

from __future__ import annotations

from cspm.models import Cloud, Resource
from cspm.providers.base import Provider


class AzureProvider(Provider):
    cloud = Cloud.AZURE

    def collect(self) -> list[Resource]:
        if self.mock:
            return self._mock_resources()
        return self._collect_live()

    def _collect_live(self) -> list[Resource]:  # pragma: no cover - needs creds
        raise NotImplementedError(
            "Live Azure collection requires azure-mgmt SDKs and credentials."
        )

    def _mock_resources(self) -> list[Resource]:
        return [
            Resource(
                id="/subscriptions/x/storageAccounts/publicdata",
                name="publicdata",
                type="storage_account",
                cloud=Cloud.AZURE,
                region="eastus",
                properties={
                    "https_only": False,
                    "allow_blob_public_access": True,
                },
            ),
            Resource(
                id="/subscriptions/x/storageAccounts/securestore",
                name="securestore",
                type="storage_account",
                cloud=Cloud.AZURE,
                region="eastus",
                properties={
                    "https_only": True,
                    "allow_blob_public_access": False,
                },
            ),
            Resource(
                id="/subscriptions/x/nsg/web-nsg",
                name="web-nsg",
                type="network_security_group",
                cloud=Cloud.AZURE,
                region="eastus",
                properties={
                    "security_rules": [
                        {
                            "direction": "Inbound",
                            "access": "Allow",
                            "source_address_prefix": "*",
                            "destination_port_range": "3389",
                        }
                    ]
                },
            ),
            Resource(
                id="/subscriptions/x/sqlServers/prod-sql",
                name="prod-sql",
                type="sql_server",
                cloud=Cloud.AZURE,
                region="eastus",
                properties={"auditing_enabled": False},
            ),
            Resource(
                id="/subscriptions/x/virtualMachines/app-vm",
                name="app-vm",
                type="virtual_machine",
                cloud=Cloud.AZURE,
                region="eastus",
                properties={"disk_encryption_enabled": True},
            ),
        ]
