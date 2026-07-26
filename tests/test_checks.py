"""Unit tests for individual checks."""

from cspm.checks.aws_checks import (
    IAMUserMFACheck,
    S3EncryptionCheck,
    S3PublicAccessCheck,
    SecurityGroupOpenSSHCheck,
)
from cspm.checks.azure_checks import NSGOpenManagementCheck, StorageAccountPublicBlobCheck
from cspm.checks.gcp_checks import (
    FirewallOpenRDPCheck,
    ServiceAccountKeyRotationCheck,
    StorageBucketPublicCheck,
)
from cspm.models import Cloud, Resource


def _res(cloud, rtype, props):
    return Resource(id="x", name="x", type=rtype, cloud=cloud, properties=props)


def test_s3_public_access_fails_when_open():
    r = _res(Cloud.AWS, "s3_bucket", {"public_access_block": {}})
    assert S3PublicAccessCheck().evaluate(r) is False


def test_s3_public_access_passes_when_blocked():
    block = {
        "block_public_acls": True,
        "ignore_public_acls": True,
        "block_public_policy": True,
        "restrict_public_buckets": True,
    }
    r = _res(Cloud.AWS, "s3_bucket", {"public_access_block": block})
    assert S3PublicAccessCheck().evaluate(r) is True


def test_s3_encryption():
    assert S3EncryptionCheck().evaluate(_res(Cloud.AWS, "s3_bucket", {"encryption_enabled": True}))
    assert not S3EncryptionCheck().evaluate(_res(Cloud.AWS, "s3_bucket", {}))


def test_sg_open_ssh():
    open_rule = {"ingress_rules": [{"from_port": 22, "to_port": 22, "cidr_blocks": ["0.0.0.0/0"]}]}
    assert SecurityGroupOpenSSHCheck().evaluate(_res(Cloud.AWS, "security_group", open_rule)) is False
    closed = {"ingress_rules": [{"from_port": 22, "to_port": 22, "cidr_blocks": ["10.0.0.0/8"]}]}
    assert SecurityGroupOpenSSHCheck().evaluate(_res(Cloud.AWS, "security_group", closed)) is True


def test_iam_mfa_ignores_non_console_users():
    r = _res(Cloud.AWS, "iam_user", {"console_access": False, "mfa_enabled": False})
    assert IAMUserMFACheck().evaluate(r) is True
    r2 = _res(Cloud.AWS, "iam_user", {"console_access": True, "mfa_enabled": False})
    assert IAMUserMFACheck().evaluate(r2) is False


def test_gcp_bucket_public():
    r = _res(Cloud.GCP, "storage_bucket", {"iam_members": ["allUsers"]})
    assert StorageBucketPublicCheck().evaluate(r) is False
    r2 = _res(Cloud.GCP, "storage_bucket", {"iam_members": ["user:a@b.com"]})
    assert StorageBucketPublicCheck().evaluate(r2) is True


def test_gcp_firewall_open_rdp():
    r = _res(
        Cloud.GCP,
        "firewall_rule",
        {"direction": "INGRESS", "source_ranges": ["0.0.0.0/0"], "allowed": [{"ports": ["3389"]}]},
    )
    assert FirewallOpenRDPCheck().evaluate(r) is False


def test_gcp_sa_key_age():
    r = _res(Cloud.GCP, "service_account", {"keys": [{"age_days": 200}]})
    assert ServiceAccountKeyRotationCheck().evaluate(r) is False
    r2 = _res(Cloud.GCP, "service_account", {"keys": [{"age_days": 5}]})
    assert ServiceAccountKeyRotationCheck().evaluate(r2) is True


def test_azure_public_blob():
    r = _res(Cloud.AZURE, "storage_account", {"allow_blob_public_access": True})
    assert StorageAccountPublicBlobCheck().evaluate(r) is False
    r2 = _res(Cloud.AZURE, "storage_account", {"allow_blob_public_access": False})
    assert StorageAccountPublicBlobCheck().evaluate(r2) is True


def test_azure_nsg_open_mgmt():
    rule = {
        "direction": "Inbound",
        "access": "Allow",
        "source_address_prefix": "*",
        "destination_port_range": "3389",
    }
    r = _res(Cloud.AZURE, "network_security_group", {"security_rules": [rule]})
    assert NSGOpenManagementCheck().evaluate(r) is False
