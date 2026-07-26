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
        collector=None,
    ) -> None:
        self.collector = collector or _LiveAzureCollector(
            tenant_id, client_id, client_secret
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

    def resource_snapshots(self) -> dict[str, dict]:
        snaps: dict[str, dict] = {}
        for sa in self.collector.storage_accounts():
            snaps[f"sa:{sa['name']}"] = {"type": "storage_account", **sa}
        for nsg in self.collector.network_security_groups():
            snaps[f"nsg:{nsg['name']}"] = {"type": "network_security_group", **nsg}
        return snaps


class _LiveAzureCollector:  # pragma: no cover - requires azure-mgmt + creds
    def __init__(self, tenant_id, client_id, client_secret) -> None:
        if not all([tenant_id, client_id, client_secret]):
            raise ValueError("Azure service-principal credentials required.")
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret

    def _not_impl(self):
        raise NotImplementedError("Live Azure collection requires azure-mgmt SDKs.")

    def storage_accounts(self):
        self._not_impl()

    def network_security_groups(self):
        self._not_impl()

    def sql_servers(self):
        self._not_impl()

    def virtual_machines(self):
        self._not_impl()
