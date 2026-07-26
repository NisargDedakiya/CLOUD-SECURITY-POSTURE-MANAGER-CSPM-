"""Tests for Module 6.2 — AWS audit engine check_* methods."""

import pytest

from cspm.auditors.aws import AWSAuditor
from cspm.fakes import FakeAWSSession


@pytest.fixture()
def auditor():
    return AWSAuditor(session=FakeAWSSession(), regions=["us-east-1"])


def test_run_all_returns_findings(auditor):
    findings = auditor.run_all()
    ids = {f.check_id for f in findings}
    # The fake account is intentionally insecure across every category.
    assert "aws_s3_public_access_block" in ids
    assert "aws_iam_root_mfa" in ids
    assert "aws_sg_open_ssh_rdp" in ids
    assert "aws_rds_public_access" in ids
    assert "aws_guardduty_enabled" in ids


def test_s3_public_access_flags_only_public_bucket(auditor):
    findings = auditor.check_s3_public_access()
    resources = {f.resource for f in findings}
    assert "arn:aws:s3:::public-bucket" in resources
    assert "arn:aws:s3:::secure-bucket" not in resources


def test_s3_encryption_flags_unencrypted(auditor):
    findings = auditor.check_s3_encryption()
    assert any("public-bucket" in f.resource for f in findings)
    assert all("secure-bucket" not in f.resource for f in findings)


def test_iam_root_mfa_critical(auditor):
    findings = auditor.check_iam_root_mfa()
    assert len(findings) == 1
    assert findings[0].severity == "critical"


def test_access_key_age(auditor):
    findings = auditor.check_iam_access_key_age()
    assert findings and "AKIAOLD" in findings[0].resource


def test_sg_open_ssh(auditor):
    findings = auditor.check_security_groups_open_ssh_rdp()
    assert findings and findings[0].severity == "high"


def test_rds_public_and_encryption(auditor):
    assert auditor.check_rds_public_access()
    assert auditor.check_rds_encryption()


def test_check_methods_are_discovered(auditor):
    methods = auditor.list_checks()
    assert "check_s3_public_access" in methods
    assert len(methods) >= 10


def test_snapshots_for_drift(auditor):
    snaps = auditor.resource_snapshots()
    assert any(k.startswith("s3:") for k in snaps)
    assert any(k.startswith("sg:") for k in snaps)


def test_one_broken_check_does_not_abort(auditor, monkeypatch):
    def boom():
        raise RuntimeError("api down")

    monkeypatch.setattr(auditor, "check_guardduty_enabled", boom)
    findings = auditor.run_all()
    # Still returns other findings, plus an error marker for the broken check.
    assert any(f.check_id == "check_guardduty_enabled_error" for f in findings)
    assert any(f.check_id == "aws_s3_public_access_block" for f in findings)
