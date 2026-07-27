"""Azure Security Audit Engine (follow-on to AWS, spec Step 5).

Mirrors the AWS class-based ``check_*`` pattern. A collector may be injected for
testing; in production it wraps azure-mgmt SDK clients authenticated via the
stored service-principal credentials.
"""

from __future__ import annotations

from cspm.auditors.base import BaseAuditor
from cspm.auditors.findings import Finding


class AzureAuditor(BaseAuditor):
    provider = "azure"

    def __init__(
        self,
        tenant_id: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        subscription_id: str | None = None,
        collector=None,
    ) -> None:
        self.collector = collector or _LiveAzureCollector(
            tenant_id, client_id, client_secret, subscription_id
        )

    def check_storage_https_only(self) -> list[Finding]:
        findings = []
        for sa in self.collector.storage_accounts():
            if not sa.get("https_only"):
                findings.append(
                    Finding(
                        resource=sa["name"],
                        check="Storage account does not require HTTPS",
                        check_id="azure_storage_https",
                        severity="high",
                        remediation="Enable 'Secure transfer required' on the storage account.",
                    )
                )
        return findings

    def check_storage_public_blob(self) -> list[Finding]:
        findings = []
        for sa in self.collector.storage_accounts():
            if sa.get("allow_blob_public_access"):
                findings.append(
                    Finding(
                        resource=sa["name"],
                        check="Storage account allows public blob access",
                        check_id="azure_storage_public_blob",
                        severity="critical",
                        remediation="Set allowBlobPublicAccess=false on the storage account.",
                    )
                )
        return findings

    def check_nsg_open_management(self) -> list[Finding]:
        findings = []
        public = {"*", "0.0.0.0/0", "internet"}
        for nsg in self.collector.network_security_groups():
            for rule in nsg.get("security_rules", []):
                if rule.get("direction", "Inbound").lower() != "inbound":
                    continue
                if rule.get("access", "Allow").lower() != "allow":
                    continue
                if str(rule.get("source_address_prefix", "")).lower() not in public:
                    continue
                port = str(rule.get("destination_port_range", ""))
                if port in {"22", "3389", "*"}:
                    findings.append(
                        Finding(
                            resource=nsg["name"],
                            check="NSG exposes management ports to the internet",
                            check_id="azure_nsg_open_mgmt",
                            severity="high",
                            remediation="Restrict inbound SSH/RDP to specific source prefixes.",
                        )
                    )
                    break
        return findings

    def check_sql_auditing(self) -> list[Finding]:
        findings = []
        for srv in self.collector.sql_servers():
            if not srv.get("auditing_enabled"):
                findings.append(
                    Finding(
                        resource=srv["name"],
                        check="SQL server auditing disabled",
                        check_id="azure_sql_auditing",
                        severity="medium",
                        remediation="Enable auditing and send logs to a Log Analytics workspace.",
                    )
                )
        return findings

    def check_vm_disk_encryption(self) -> list[Finding]:
        findings = []
        for vm in self.collector.virtual_machines():
            if not vm.get("disk_encryption_enabled"):
                findings.append(
                    Finding(
                        resource=vm["name"],
                        check="VM disks are not encrypted",
                        check_id="azure_vm_disk_encryption",
                        severity="high",
                        remediation="Enable Azure Disk Encryption or encryption at host.",
                    )
                )
        return findings

    def check_storage_min_tls(self) -> list[Finding]:
        findings = []
        for sa in self.collector.storage_accounts():
            tls = str(sa.get("min_tls_version", "")).replace("_", ".")
            if tls and tls < "TLS1.2":
                findings.append(
                    Finding(
                        resource=sa["name"],
                        check="Storage account allows TLS below 1.2",
                        check_id="azure_storage_min_tls",
                        severity="medium",
                        remediation="Set the storage account minimum TLS version to 1.2.",
                    )
                )
        return findings

    def check_keyvault_soft_delete(self) -> list[Finding]:
        findings = []
        for kv in self.collector.key_vaults():
            if not kv.get("soft_delete_enabled") or not kv.get("purge_protection"):
                findings.append(
                    Finding(
                        resource=kv["name"],
                        check="Key Vault missing soft-delete / purge protection",
                        check_id="azure_keyvault_protection",
                        severity="high",
                        remediation="Enable soft-delete and purge protection on the Key Vault.",
                    )
                )
        return findings

    def resource_snapshots(self) -> dict[str, dict]:
        snaps: dict[str, dict] = {}
        for sa in self.collector.storage_accounts():
            snaps[f"sa:{sa['name']}"] = {"type": "storage_account", **sa}
        for nsg in self.collector.network_security_groups():
            snaps[f"nsg:{nsg['name']}"] = {"type": "network_security_group", **nsg}
        return snaps


class _LiveAzureCollector:  # pragma: no cover - requires azure-mgmt + creds
    """Live Azure collector backed by the azure-mgmt SDKs.

    Install with ``pip install -e ".[azure]"``. Authenticates a service principal
    (Reader on the subscription) via azure-identity.
    """

    def __init__(self, tenant_id, client_id, client_secret, subscription_id) -> None:
        if not all([tenant_id, client_id, client_secret, subscription_id]):
            raise ValueError("Azure credentials + subscription_id required.")
        from azure.identity import ClientSecretCredential

        self.subscription_id = subscription_id
        self._cred = ClientSecretCredential(tenant_id, client_id, client_secret)

    def storage_accounts(self) -> list[dict]:
        from azure.mgmt.storage import StorageManagementClient

        client = StorageManagementClient(self._cred, self.subscription_id)
        out = []
        for sa in client.storage_accounts.list():
            out.append(
                {
                    "name": sa.name,
                    "https_only": bool(getattr(sa, "enable_https_traffic_only", False)),
                    "allow_blob_public_access": bool(
                        getattr(sa, "allow_blob_public_access", False)
                    ),
                    "min_tls_version": getattr(sa, "minimum_tls_version", "TLS1_2"),
                }
            )
        return out

    def network_security_groups(self) -> list[dict]:
        from azure.mgmt.network import NetworkManagementClient

        client = NetworkManagementClient(self._cred, self.subscription_id)
        out = []
        for nsg in client.network_security_groups.list_all():
            rules = [
                {
                    "direction": r.direction,
                    "access": r.access,
                    "source_address_prefix": r.source_address_prefix or "",
                    "destination_port_range": r.destination_port_range or "",
                }
                for r in (nsg.security_rules or [])
            ]
            out.append({"name": nsg.name, "security_rules": rules})
        return out

    def sql_servers(self) -> list[dict]:
        from azure.mgmt.sql import SqlManagementClient

        client = SqlManagementClient(self._cred, self.subscription_id)
        out = []
        for srv in client.servers.list():
            rg = srv.id.split("/")[4]
            auditing = client.server_blob_auditing_policies.get(rg, srv.name)
            out.append(
                {"name": srv.name, "auditing_enabled": auditing.state == "Enabled"}
            )
        return out

    def virtual_machines(self) -> list[dict]:
        from azure.mgmt.compute import ComputeManagementClient

        client = ComputeManagementClient(self._cred, self.subscription_id)
        out = []
        for vm in client.virtual_machines.list_all():
            encrypted = bool(
                getattr(getattr(vm, "security_profile", None), "encryption_at_host", False)
            )
            out.append({"name": vm.name, "disk_encryption_enabled": encrypted})
        return out

    def key_vaults(self) -> list[dict]:
        from azure.mgmt.keyvault import KeyVaultManagementClient

        client = KeyVaultManagementClient(self._cred, self.subscription_id)
        out = []
        for kv in client.vaults.list_by_subscription():
            props = getattr(kv, "properties", None)
            out.append({
                "name": kv.name,
                "soft_delete_enabled": bool(getattr(props, "enable_soft_delete", False)),
                "purge_protection": bool(getattr(props, "enable_purge_protection", False)),
            })
        return out
