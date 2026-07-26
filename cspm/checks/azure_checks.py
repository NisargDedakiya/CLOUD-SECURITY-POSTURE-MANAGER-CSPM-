"""Azure security posture checks."""

from __future__ import annotations

from cspm.checks.base import Check
from cspm.models import Cloud, Resource, Severity


class StorageAccountHTTPSCheck(Check):
    check_id = "AZURE_STORAGE_HTTPS"
    title = "Storage account requires secure transfer (HTTPS)"
    cloud = Cloud.AZURE
    resource_type = "storage_account"
    severity = Severity.HIGH
    description = "Storage accounts must require secure transfer (HTTPS only)."
    remediation = "Enable 'Secure transfer required' on the storage account."

    def evaluate(self, resource: Resource) -> bool:
        return bool(resource.properties.get("https_only"))


class StorageAccountPublicBlobCheck(Check):
    check_id = "AZURE_STORAGE_PUBLIC_BLOB"
    title = "Storage account disallows public blob access"
    cloud = Cloud.AZURE
    resource_type = "storage_account"
    severity = Severity.CRITICAL
    description = "Storage accounts must not allow anonymous public blob access."
    remediation = "Set 'allowBlobPublicAccess' to false on the storage account."

    def evaluate(self, resource: Resource) -> bool:
        return resource.properties.get("allow_blob_public_access") is False


class NSGOpenManagementCheck(Check):
    check_id = "AZURE_NSG_OPEN_MGMT"
    title = "NSG does not expose management ports to internet"
    cloud = Cloud.AZURE
    resource_type = "network_security_group"
    severity = Severity.HIGH
    description = "NSGs must not allow inbound 22/3389 from the internet (*/Internet)."
    remediation = "Restrict inbound RDP/SSH rules to specific source address prefixes."

    def evaluate(self, resource: Resource) -> bool:
        public_sources = {"*", "0.0.0.0/0", "internet"}
        mgmt_ports = {"22", "3389"}
        for rule in resource.properties.get("security_rules", []):
            if rule.get("direction", "Inbound").lower() != "inbound":
                continue
            if rule.get("access", "Allow").lower() != "allow":
                continue
            src = str(rule.get("source_address_prefix", "")).lower()
            if src not in public_sources:
                continue
            port = str(rule.get("destination_port_range", ""))
            if port in mgmt_ports or port == "*":
                return False
        return True


class SQLServerAuditingCheck(Check):
    check_id = "AZURE_SQL_AUDITING"
    title = "SQL server has auditing enabled"
    cloud = Cloud.AZURE
    resource_type = "sql_server"
    severity = Severity.MEDIUM
    description = "Azure SQL servers must have auditing enabled."
    remediation = "Enable auditing on the SQL server and send logs to a Log Analytics workspace."

    def evaluate(self, resource: Resource) -> bool:
        return bool(resource.properties.get("auditing_enabled"))


class VMDiskEncryptionCheck(Check):
    check_id = "AZURE_VM_DISK_ENCRYPTION"
    title = "VM disks are encrypted"
    cloud = Cloud.AZURE
    resource_type = "virtual_machine"
    severity = Severity.HIGH
    description = "Virtual machine OS/data disks must be encrypted."
    remediation = "Enable Azure Disk Encryption or encryption at host for the VM."

    def evaluate(self, resource: Resource) -> bool:
        return bool(resource.properties.get("disk_encryption_enabled"))
