"""AWS security posture checks."""

from __future__ import annotations

from cspm.checks.base import Check
from cspm.models import Cloud, Resource, Severity


class S3PublicAccessCheck(Check):
    check_id = "AWS_S3_PUBLIC_ACCESS"
    title = "S3 bucket blocks public access"
    cloud = Cloud.AWS
    resource_type = "s3_bucket"
    severity = Severity.CRITICAL
    description = "S3 buckets must have all public access block settings enabled."
    remediation = (
        "Enable 'Block all public access' on the bucket "
        "(BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets)."
    )

    def evaluate(self, resource: Resource) -> bool:
        block = resource.properties.get("public_access_block", {})
        required = [
            "block_public_acls",
            "ignore_public_acls",
            "block_public_policy",
            "restrict_public_buckets",
        ]
        return all(block.get(k) is True for k in required)


class S3EncryptionCheck(Check):
    check_id = "AWS_S3_ENCRYPTION"
    title = "S3 bucket has default encryption"
    cloud = Cloud.AWS
    resource_type = "s3_bucket"
    severity = Severity.HIGH
    description = "S3 buckets must enable default server-side encryption."
    remediation = "Enable default encryption (SSE-S3 or SSE-KMS) on the bucket."

    def evaluate(self, resource: Resource) -> bool:
        return bool(resource.properties.get("encryption_enabled"))


class SecurityGroupOpenSSHCheck(Check):
    check_id = "AWS_SG_OPEN_SSH"
    title = "Security group does not allow 0.0.0.0/0 to SSH"
    cloud = Cloud.AWS
    resource_type = "security_group"
    severity = Severity.HIGH
    description = "Security groups must not expose port 22 (SSH) to the internet."
    remediation = "Restrict inbound port 22 to known CIDR ranges, not 0.0.0.0/0."

    def evaluate(self, resource: Resource) -> bool:
        for rule in resource.properties.get("ingress_rules", []):
            from_p = rule.get("from_port", 0)
            to_p = rule.get("to_port", 0)
            cidrs = rule.get("cidr_blocks", [])
            if from_p <= 22 <= to_p and "0.0.0.0/0" in cidrs:
                return False
        return True


class IAMUserMFACheck(Check):
    check_id = "AWS_IAM_USER_MFA"
    title = "IAM user has MFA enabled"
    cloud = Cloud.AWS
    resource_type = "iam_user"
    severity = Severity.HIGH
    description = "IAM users with console access must have MFA enabled."
    remediation = "Enable a virtual or hardware MFA device for the IAM user."

    def evaluate(self, resource: Resource) -> bool:
        if not resource.properties.get("console_access"):
            return True
        return bool(resource.properties.get("mfa_enabled"))


class RDSEncryptionCheck(Check):
    check_id = "AWS_RDS_ENCRYPTION"
    title = "RDS instance storage is encrypted"
    cloud = Cloud.AWS
    resource_type = "rds_instance"
    severity = Severity.HIGH
    description = "RDS instances must have storage encryption enabled at rest."
    remediation = "Recreate the RDS instance with 'StorageEncrypted' set to true."

    def evaluate(self, resource: Resource) -> bool:
        return bool(resource.properties.get("storage_encrypted"))
