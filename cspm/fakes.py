"""In-memory fake boto3 session for demos and tests.

Returns realistic, intentionally-insecure AWS responses so the AWSAuditor can
run end-to-end without real credentials. Only the calls the auditor makes are
implemented.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta


class _ClientError(Exception):
    """Stand-in for botocore ClientError (auditor only checks the type)."""


def _client_error(code: str):
    """Build a botocore ClientError (or the stub) with the right constructor."""
    from botocore.exceptions import ClientError

    try:
        return ClientError({"Error": {"Code": code, "Message": code}}, "FakeOp")
    except TypeError:  # our minimal stub takes a single arg
        return ClientError(code)


def _install_botocore_stub() -> None:
    """Ensure ``botocore.exceptions.ClientError`` resolves in test envs."""
    try:
        import botocore.exceptions  # noqa: F401
    except Exception:  # noqa: BLE001 - provide a minimal stub
        import sys
        import types

        botocore = types.ModuleType("botocore")
        exceptions = types.ModuleType("botocore.exceptions")
        exceptions.ClientError = _ClientError
        botocore.exceptions = exceptions
        sys.modules["botocore"] = botocore
        sys.modules["botocore.exceptions"] = exceptions


class _FakeS3:
    def list_buckets(self):
        return {"Buckets": [{"Name": "public-bucket"}, {"Name": "secure-bucket"}]}

    def get_public_access_block(self, Bucket):  # noqa: N803 - boto3 signature
        if Bucket == "secure-bucket":
            return {
                "PublicAccessBlockConfiguration": {
                    "BlockPublicAcls": True,
                    "BlockPublicPolicy": True,
                    "IgnorePublicAcls": True,
                    "RestrictPublicBuckets": True,
                }
            }
        return {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": False,
                "BlockPublicPolicy": False,
                "IgnorePublicAcls": False,
                "RestrictPublicBuckets": False,
            }
        }

    def get_bucket_encryption(self, Bucket):  # noqa: N803
        if Bucket == "secure-bucket":
            return {"ServerSideEncryptionConfiguration": {"Rules": []}}
        raise _client_error("ServerSideEncryptionConfigurationNotFoundError")

    def get_bucket_versioning(self, Bucket):  # noqa: N803
        return {"Status": "Enabled"} if Bucket == "secure-bucket" else {}

    def get_bucket_logging(self, Bucket):  # noqa: N803
        return {"LoggingEnabled": {"TargetBucket": "logs"}} if Bucket == "secure-bucket" else {}


class _FakeIAM:
    def get_account_summary(self):
        return {"SummaryMap": {"AccountMFAEnabled": 0}}

    def get_account_password_policy(self):
        return {"PasswordPolicy": {"MinimumPasswordLength": 8}}

    def list_users(self):
        return {"Users": [{"UserName": "alice"}]}

    def list_access_keys(self, UserName):  # noqa: N803
        old = datetime.now(UTC) - timedelta(days=200)
        return {
            "AccessKeyMetadata": [
                {"AccessKeyId": "AKIAOLD", "Status": "Active", "CreateDate": old}
            ]
        }

    def list_attached_user_policies(self, UserName):  # noqa: N803
        return {"AttachedPolicies": [{"PolicyName": "AdministratorAccess"}]}

    def list_mfa_devices(self, UserName):  # noqa: N803
        return {"MFADevices": []}  # no MFA → finding


class _FakeEC2:
    def describe_security_groups(self):
        return {
            "SecurityGroups": [
                {
                    "GroupId": "sg-open",
                    "IpPermissions": [
                        {
                            "FromPort": 22,
                            "ToPort": 22,
                            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                        }
                    ],
                }
            ]
        }

    def describe_instances(self):
        return {
            "Reservations": [
                {
                    "Instances": [
                        {"InstanceId": "i-123", "MetadataOptions": {"HttpTokens": "optional"}}
                    ]
                }
            ]
        }

    def get_ebs_encryption_by_default(self):
        return {"EbsEncryptionByDefault": False}

    def describe_volumes(self):
        return {"Volumes": [{"VolumeId": "vol-abc", "Encrypted": False}]}

    def describe_vpcs(self):
        return {"Vpcs": [{"VpcId": "vpc-123"}]}

    def describe_flow_logs(self):
        return {"FlowLogs": []}  # no flow logs → finding


class _FakeRDS:
    def describe_db_instances(self):
        return {
            "DBInstances": [
                {
                    "DBInstanceIdentifier": "prod-db",
                    "PubliclyAccessible": True,
                    "StorageEncrypted": False,
                }
            ]
        }


class _FakeCloudTrail:
    def describe_trails(self):
        return {"trailList": [{"Name": "t", "IsMultiRegionTrail": False, "LogFileValidationEnabled": False}]}


class _FakeSecretsManager:
    def list_secrets(self):
        return {"SecretList": [{"Name": "db-password", "ARN": "arn:sm:db", "RotationEnabled": False}]}


class _FakeKMS:
    def list_keys(self):
        return {"Keys": [{"KeyId": "key-1"}]}

    def get_key_rotation_status(self, KeyId):  # noqa: N803
        return {"KeyRotationEnabled": False}


class _FakeGuardDuty:
    def list_detectors(self):
        return {"DetectorIds": []}


class _FakeSTS:
    def get_caller_identity(self):
        return {"Account": "123456789012", "Arn": "arn:aws:sts::123456789012:assumed-role/x"}


class FakeGCPCollector:
    """Intentionally-insecure GCP resources for demos/tests."""

    def buckets(self):
        return [
            {"name": "public-assets", "iam_members": ["allUsers"], "uniform_bucket_level_access": False},
            {"name": "internal", "iam_members": ["user:ops@x"], "uniform_bucket_level_access": True},
        ]

    def firewalls(self):
        return [
            {
                "name": "allow-rdp",
                "direction": "INGRESS",
                "source_ranges": ["0.0.0.0/0"],
                "allowed": [{"ports": ["3389"]}],
            }
        ]

    def instances(self):
        return [{"name": "web-1", "has_public_ip": True}]

    def service_accounts(self):
        return [{"email": "deploy@x.iam", "keys": [{"age_days": 120}]}]


class FakeAzureCollector:
    """Intentionally-insecure Azure resources for demos/tests."""

    def storage_accounts(self):
        return [
            {"name": "publicdata", "https_only": False, "allow_blob_public_access": True},
            {"name": "securestore", "https_only": True, "allow_blob_public_access": False},
        ]

    def network_security_groups(self):
        return [
            {
                "name": "web-nsg",
                "security_rules": [
                    {
                        "direction": "Inbound",
                        "access": "Allow",
                        "source_address_prefix": "*",
                        "destination_port_range": "3389",
                    }
                ],
            }
        ]

    def sql_servers(self):
        return [{"name": "prod-sql", "auditing_enabled": False}]

    def virtual_machines(self):
        return [{"name": "app-vm", "disk_encryption_enabled": False}]


class FakeAWSSession:
    """Mimics boto3.Session.client for the services the auditor uses."""

    _MAP = {
        "s3": _FakeS3,
        "iam": _FakeIAM,
        "ec2": _FakeEC2,
        "rds": _FakeRDS,
        "cloudtrail": _FakeCloudTrail,
        "kms": _FakeKMS,
        "guardduty": _FakeGuardDuty,
        "sts": _FakeSTS,
        "secretsmanager": _FakeSecretsManager,
    }

    def __init__(self) -> None:
        _install_botocore_stub()

    def client(self, service, region_name=None):
        return self._MAP[service]()
