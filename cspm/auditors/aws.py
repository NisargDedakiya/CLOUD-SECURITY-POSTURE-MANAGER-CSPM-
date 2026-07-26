"""Module 6.2 — AWS Security Audit Engine.

``AWSAuditor`` assumes the customer's read-only cross-account role via STS (with
an external id to prevent the confused-deputy problem) and runs a suite of
independently-testable ``check_*`` methods against the account.

Testability: a boto3 ``Session`` may be injected via ``session=`` to bypass the
live ``AssumeRole`` call, so each check can be exercised with fake clients.
"""

from __future__ import annotations

from datetime import UTC, datetime

from cspm.auditors.base import BaseAuditor
from cspm.auditors.findings import Finding
from cspm.config import get_settings

# Regions scanned for regional services. In production this is discovered via
# ec2.describe_regions(); kept short here to bound API calls in dev/tests.
DEFAULT_REGIONS = ["us-east-1", "us-west-2", "eu-west-1"]
ACCESS_KEY_MAX_AGE_DAYS = 90


class AWSAuditor(BaseAuditor):
    provider = "aws"

    def __init__(
        self,
        role_arn: str | None = None,
        external_id: str | None = None,
        session=None,
        regions: list[str] | None = None,
    ) -> None:
        self.role_arn = role_arn
        self.external_id = external_id
        if session is not None:
            self.session = session
        else:
            self.session = self._assume_role(role_arn, external_id)
        # Live region discovery when not explicitly provided and not a fake session.
        self.regions = regions or self._discover_regions()

    def _discover_regions(self) -> list[str]:
        """Enumerate enabled regions; fall back to a safe default set."""
        try:
            ec2 = self.session.client("ec2", region_name="us-east-1")
            resp = ec2.describe_regions(AllRegions=False)
            found = [r["RegionName"] for r in resp.get("Regions", [])]
            return found or DEFAULT_REGIONS
        except Exception:  # noqa: BLE001 - fakes/limited perms → default set
            return DEFAULT_REGIONS

    @staticmethod
    def _assume_role(role_arn: str | None, external_id: str | None):  # pragma: no cover
        import boto3

        if not role_arn:
            raise ValueError("role_arn is required for live AWS auditing.")
        sts = boto3.client("sts")
        kwargs = {
            "RoleArn": role_arn,
            "RoleSessionName": get_settings().aws_role_session_name,
        }
        if external_id:
            kwargs["ExternalId"] = external_id
        creds = sts.assume_role(**kwargs)["Credentials"]
        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
        )

    # ---- IAM ---------------------------------------------------------------
    def check_iam_root_mfa(self) -> list[Finding]:
        iam = self.session.client("iam")
        summary = iam.get_account_summary().get("SummaryMap", {})
        if summary.get("AccountMFAEnabled", 0) != 1:
            return [
                Finding(
                    resource="root-account",
                    check="Root account MFA not enabled",
                    check_id="aws_iam_root_mfa",
                    severity="critical",
                    remediation="Enable a hardware or virtual MFA device on the root account.",
                )
            ]
        return []

    def check_iam_password_policy(self) -> list[Finding]:
        from botocore.exceptions import ClientError

        iam = self.session.client("iam")
        try:
            policy = iam.get_account_password_policy()["PasswordPolicy"]
        except ClientError:
            return [
                Finding(
                    resource="account-password-policy",
                    check="No IAM account password policy set",
                    check_id="aws_iam_password_policy",
                    severity="high",
                    remediation="Set a password policy: min length 14, complexity, 90-day rotation.",
                )
            ]
        findings = []
        if policy.get("MinimumPasswordLength", 0) < 14:
            findings.append(
                Finding(
                    resource="account-password-policy",
                    check="IAM password policy minimum length below 14",
                    check_id="aws_iam_password_policy",
                    severity="medium",
                    remediation="Increase minimum password length to at least 14 characters.",
                )
            )
        return findings

    def check_iam_access_key_age(self) -> list[Finding]:
        iam = self.session.client("iam")
        findings: list[Finding] = []
        now = datetime.now(UTC)
        for user in iam.list_users().get("Users", []):
            uname = user["UserName"]
            for key in iam.list_access_keys(UserName=uname).get("AccessKeyMetadata", []):
                created = key.get("CreateDate")
                if created is None:
                    continue
                if created.tzinfo is None:
                    created = created.replace(tzinfo=UTC)
                age = (now - created).days
                if key.get("Status") == "Active" and age > ACCESS_KEY_MAX_AGE_DAYS:
                    findings.append(
                        Finding(
                            resource=f"iam-user/{uname}/{key['AccessKeyId']}",
                            check="IAM access key older than 90 days",
                            check_id="aws_iam_access_key_age",
                            severity="medium",
                            remediation="Rotate the access key and delete keys older than 90 days.",
                            description=f"Access key is {age} days old.",
                        )
                    )
        return findings

    def check_iam_wildcard_policies(self) -> list[Finding]:
        iam = self.session.client("iam")
        findings: list[Finding] = []
        for user in iam.list_users().get("Users", []):
            uname = user["UserName"]
            attached = iam.list_attached_user_policies(UserName=uname).get(
                "AttachedPolicies", []
            )
            for pol in attached:
                if pol.get("PolicyName") == "AdministratorAccess":
                    findings.append(
                        Finding(
                            resource=f"iam-user/{uname}",
                            check="AdministratorAccess attached directly to IAM user",
                            check_id="aws_iam_wildcard_policies",
                            severity="high",
                            remediation="Grant admin via a group/role, not directly on users; avoid wildcard '*'.",
                        )
                    )
        return findings

    # ---- S3 ----------------------------------------------------------------
    def check_s3_public_access(self) -> list[Finding]:
        from botocore.exceptions import ClientError

        s3 = self.session.client("s3")
        findings: list[Finding] = []
        for bucket in s3.list_buckets().get("Buckets", []):
            name = bucket["Name"]
            try:
                pab = s3.get_public_access_block(Bucket=name)
                config = pab["PublicAccessBlockConfiguration"]
                if not all(
                    [
                        config.get("BlockPublicAcls"),
                        config.get("BlockPublicPolicy"),
                        config.get("IgnorePublicAcls"),
                        config.get("RestrictPublicBuckets"),
                    ]
                ):
                    findings.append(
                        Finding(
                            resource=f"arn:aws:s3:::{name}",
                            check="S3 Public Access Block Not Fully Enabled",
                            check_id="aws_s3_public_access_block",
                            severity="high",
                            remediation="Enable all four S3 Block Public Access settings at bucket level.",
                        )
                    )
            except ClientError:
                # Block not configured at all = finding.
                findings.append(
                    Finding(
                        resource=f"arn:aws:s3:::{name}",
                        check="S3 Public Access Block Not Configured",
                        check_id="aws_s3_public_access_block",
                        severity="high",
                        remediation="Enable all four S3 Block Public Access settings at bucket level.",
                    )
                )
        return findings

    def check_s3_encryption(self) -> list[Finding]:
        from botocore.exceptions import ClientError

        s3 = self.session.client("s3")
        findings: list[Finding] = []
        for bucket in s3.list_buckets().get("Buckets", []):
            name = bucket["Name"]
            try:
                s3.get_bucket_encryption(Bucket=name)
            except ClientError:
                findings.append(
                    Finding(
                        resource=f"arn:aws:s3:::{name}",
                        check="S3 bucket has no default encryption",
                        check_id="aws_s3_encryption",
                        severity="high",
                        remediation="Enable default SSE-S3 or SSE-KMS encryption on the bucket.",
                    )
                )
        return findings

    # ---- EC2 / VPC ---------------------------------------------------------
    def check_security_groups_open_ssh_rdp(self) -> list[Finding]:
        findings: list[Finding] = []
        risky_ports = {22: "SSH", 3389: "RDP"}
        for region in self.regions:
            ec2 = self.session.client("ec2", region_name=region)
            for sg in ec2.describe_security_groups().get("SecurityGroups", []):
                for perm in sg.get("IpPermissions", []):
                    from_p = perm.get("FromPort", 0) or 0
                    to_p = perm.get("ToPort", 0) or 0
                    open_cidr = any(
                        ip.get("CidrIp") == "0.0.0.0/0" for ip in perm.get("IpRanges", [])
                    )
                    if not open_cidr:
                        continue
                    for port, label in risky_ports.items():
                        if from_p <= port <= to_p:
                            findings.append(
                                Finding(
                                    resource=f"{region}/{sg['GroupId']}",
                                    check=f"Security group allows 0.0.0.0/0 to {label}",
                                    check_id="aws_sg_open_ssh_rdp",
                                    severity="high",
                                    remediation=f"Restrict inbound port {port} ({label}) to known CIDRs.",
                                    region=region,
                                )
                            )
        return findings

    def check_ec2_imdsv2(self) -> list[Finding]:
        findings: list[Finding] = []
        for region in self.regions:
            ec2 = self.session.client("ec2", region_name=region)
            for res in ec2.describe_instances().get("Reservations", []):
                for inst in res.get("Instances", []):
                    meta = inst.get("MetadataOptions", {})
                    if meta.get("HttpTokens") != "required":
                        findings.append(
                            Finding(
                                resource=f"{region}/{inst['InstanceId']}",
                                check="EC2 instance does not enforce IMDSv2",
                                check_id="aws_ec2_imdsv2",
                                severity="medium",
                                remediation="Set MetadataOptions HttpTokens=required to enforce IMDSv2.",
                                region=region,
                            )
                        )
        return findings

    # ---- RDS ---------------------------------------------------------------
    def check_rds_public_access(self) -> list[Finding]:
        findings: list[Finding] = []
        for region in self.regions:
            rds = self.session.client("rds", region_name=region)
            for db in rds.describe_db_instances().get("DBInstances", []):
                if db.get("PubliclyAccessible"):
                    findings.append(
                        Finding(
                            resource=f"{region}/{db['DBInstanceIdentifier']}",
                            check="RDS instance is publicly accessible",
                            check_id="aws_rds_public_access",
                            severity="critical",
                            remediation="Disable public accessibility on the RDS instance.",
                            region=region,
                        )
                    )
        return findings

    def check_rds_encryption(self) -> list[Finding]:
        findings: list[Finding] = []
        for region in self.regions:
            rds = self.session.client("rds", region_name=region)
            for db in rds.describe_db_instances().get("DBInstances", []):
                if not db.get("StorageEncrypted"):
                    findings.append(
                        Finding(
                            resource=f"{region}/{db['DBInstanceIdentifier']}",
                            check="RDS storage not encrypted",
                            check_id="aws_rds_encryption",
                            severity="high",
                            remediation="Recreate the RDS instance with StorageEncrypted=true.",
                            region=region,
                        )
                    )
        return findings

    # ---- CloudTrail / Logging ---------------------------------------------
    def check_cloudtrail_enabled(self) -> list[Finding]:
        ct = self.session.client("cloudtrail", region_name=self.regions[0])
        trails = ct.describe_trails().get("trailList", [])
        multi_region = any(t.get("IsMultiRegionTrail") for t in trails)
        if not multi_region:
            return [
                Finding(
                    resource="cloudtrail",
                    check="No multi-region CloudTrail enabled",
                    check_id="aws_cloudtrail_enabled",
                    severity="high",
                    remediation="Enable a multi-region CloudTrail with log file validation.",
                )
            ]
        return []

    # ---- KMS ---------------------------------------------------------------
    def check_kms_key_rotation(self) -> list[Finding]:
        findings: list[Finding] = []
        for region in self.regions:
            kms = self.session.client("kms", region_name=region)
            for key in kms.list_keys().get("Keys", []):
                key_id = key["KeyId"]
                try:
                    rotating = kms.get_key_rotation_status(KeyId=key_id).get(
                        "KeyRotationEnabled"
                    )
                except Exception:  # noqa: BLE001 - AWS-managed keys can't be queried
                    continue
                if not rotating:
                    findings.append(
                        Finding(
                            resource=f"{region}/{key_id}",
                            check="KMS key rotation disabled",
                            check_id="aws_kms_key_rotation",
                            severity="medium",
                            remediation="Enable automatic annual key rotation on the CMK.",
                            region=region,
                        )
                    )
        return findings

    # ---- GuardDuty ---------------------------------------------------------
    def check_guardduty_enabled(self) -> list[Finding]:
        findings: list[Finding] = []
        for region in self.regions:
            gd = self.session.client("guardduty", region_name=region)
            if not gd.list_detectors().get("DetectorIds"):
                findings.append(
                    Finding(
                        resource=f"{region}/guardduty",
                        check="GuardDuty not enabled",
                        check_id="aws_guardduty_enabled",
                        severity="high",
                        remediation="Enable GuardDuty in this region to close the detection gap.",
                        region=region,
                    )
                )
        return findings

    # ---- Drift snapshots ---------------------------------------------------
    def resource_snapshots(self) -> dict[str, dict]:
        """Normalized config for drift detection (security-sensitive resources)."""
        snapshots: dict[str, dict] = {}
        s3 = self.session.client("s3")
        for bucket in s3.list_buckets().get("Buckets", []):
            name = bucket["Name"]
            snapshots[f"s3:{name}"] = {"type": "s3_bucket", "name": name}
        for region in self.regions:
            ec2 = self.session.client("ec2", region_name=region)
            for sg in ec2.describe_security_groups().get("SecurityGroups", []):
                snapshots[f"sg:{sg['GroupId']}"] = {
                    "type": "security_group",
                    "ingress": sg.get("IpPermissions", []),
                }
        return snapshots
