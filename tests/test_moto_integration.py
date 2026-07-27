"""Integration tests for the AWS auditor against *real boto3 response shapes*,
using moto to mock the AWS APIs. This validates the live scan path without any
real cloud credentials — the honest substitute for a sandbox AWS account.
"""


import pytest

moto = pytest.importorskip("moto")
import boto3  # noqa: E402
from moto import mock_aws  # noqa: E402

from cspm.auditors.aws import AWSAuditor  # noqa: E402


@pytest.fixture()
def aws_creds(monkeypatch):
    for k, v in {
        "AWS_ACCESS_KEY_ID": "testing",
        "AWS_SECRET_ACCESS_KEY": "testing",
        "AWS_SECURITY_TOKEN": "testing",
        "AWS_SESSION_TOKEN": "testing",
        "AWS_DEFAULT_REGION": "us-east-1",
    }.items():
        monkeypatch.setenv(k, v)


@mock_aws
def test_s3_public_bucket_detected(aws_creds):
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="insecure-bucket")  # no public access block, no encryption
    auditor = AWSAuditor(session=boto3.Session(), regions=["us-east-1"])

    pab = auditor.check_s3_public_access()
    assert any("insecure-bucket" in f.resource for f in pab)
    enc = auditor.check_s3_encryption()
    assert any("insecure-bucket" in f.resource for f in enc)


@mock_aws
def test_security_group_open_ssh_detected(aws_creds):
    ec2 = boto3.client("ec2", region_name="us-east-1")
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    sg = ec2.create_security_group(GroupName="open", Description="d", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=sg,
        IpPermissions=[{
            "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        }],
    )
    auditor = AWSAuditor(session=boto3.Session(), regions=["us-east-1"])
    findings = auditor.check_security_groups_open_ssh_rdp()
    assert any(sg in f.resource for f in findings)
    assert all(f.severity == "high" for f in findings)


@mock_aws
def test_rds_unencrypted_public_detected(aws_creds):
    rds = boto3.client("rds", region_name="us-east-1")
    rds.create_db_instance(
        DBInstanceIdentifier="prod-db",
        Engine="postgres",
        DBInstanceClass="db.t3.micro",
        MasterUsername="admin",
        MasterUserPassword="password123",
        AllocatedStorage=20,
        PubliclyAccessible=True,
        StorageEncrypted=False,
    )
    auditor = AWSAuditor(session=boto3.Session(), regions=["us-east-1"])
    assert any("prod-db" in f.resource for f in auditor.check_rds_public_access())
    assert any("prod-db" in f.resource for f in auditor.check_rds_encryption())


@mock_aws
def test_region_autodiscovery_returns_real_regions(aws_creds):
    # No explicit regions → the auditor discovers them via ec2.describe_regions.
    auditor = AWSAuditor(session=boto3.Session())
    assert "us-east-1" in auditor.regions
    assert len(auditor.regions) > 1


@mock_aws
def test_s3_versioning_and_logging_gaps(aws_creds):
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="no-versioning")  # versioning off, no logging by default
    auditor = AWSAuditor(session=boto3.Session(), regions=["us-east-1"])
    assert any("no-versioning" in f.resource for f in auditor.check_s3_versioning())
    assert any("no-versioning" in f.resource for f in auditor.check_s3_access_logging())


@mock_aws
def test_ebs_default_encryption_off(aws_creds):
    auditor = AWSAuditor(session=boto3.Session(), regions=["us-east-1"])
    findings = auditor.check_ebs_encryption_by_default()
    assert any(f.check_id == "aws_ebs_default_encryption" for f in findings)


@mock_aws
def test_unencrypted_ebs_volume_detected(aws_creds):
    ec2 = boto3.client("ec2", region_name="us-east-1")
    ec2.create_volume(AvailabilityZone="us-east-1a", Size=8, Encrypted=False)
    auditor = AWSAuditor(session=boto3.Session(), regions=["us-east-1"])
    assert any(f.check_id == "aws_ebs_volume_encryption" for f in auditor.check_ebs_volume_encryption())


@mock_aws
def test_iam_user_without_mfa_detected(aws_creds):
    iam = boto3.client("iam")
    iam.create_user(UserName="bob")
    auditor = AWSAuditor(session=boto3.Session(), regions=["us-east-1"])
    findings = auditor.check_iam_user_mfa()
    assert any("bob" in f.resource for f in findings)


@mock_aws
def test_run_all_end_to_end(aws_creds):
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="e2e-bucket")
    auditor = AWSAuditor(session=boto3.Session(), regions=["us-east-1"])
    findings = auditor.run_all()
    ids = {f.check_id for f in findings}
    # Real boto3 shapes flow through every check without raising.
    assert "aws_s3_public_access_block" in ids
    assert not any(f.check_id.endswith("_error") for f in findings)
