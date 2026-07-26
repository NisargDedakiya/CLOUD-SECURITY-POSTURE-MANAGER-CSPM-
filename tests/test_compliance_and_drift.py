"""Tests for Module 6.3 (compliance) and 6.4 (drift)."""

from cspm.auditors.findings import Finding
from cspm.compliance import compute_scores, evidence_report, remediation_priority
from cspm.compliance.mappings import SEED_MAPPINGS, seed_mappings
from cspm.drift.detector import diff_snapshots, is_security_sensitive
from cspm.models import ComplianceMapping


def test_perfect_score_when_no_failures():
    scores = compute_scores(set())
    for data in scores.values():
        assert data["score"] == 100.0


def test_score_drops_with_failures():
    scores = compute_scores({"aws_s3_public_access_block"})
    cis = scores["cis_aws_v2"]
    assert cis["checks_failed"] == 1
    assert cis["score"] < 100.0


def test_remediation_priority_orders_by_control_impact():
    high_impact = Finding("r1", "cloudtrail", "high", "fix", check_id="aws_cloudtrail_enabled")
    low_impact = Finding("r2", "imds", "medium", "fix", check_id="aws_ec2_imdsv2")
    ordered = remediation_priority([low_impact, high_impact])
    assert ordered[0].check_id == "aws_cloudtrail_enabled"


def test_evidence_report_marks_pass_and_fail():
    findings = [Finding("arn:x", "s3", "high", "fix", check_id="aws_s3_encryption")]
    report = evidence_report("cis_aws_v2", findings)
    results = {c["check_id"]: c["result"] for c in report["controls"]}
    assert results["aws_s3_encryption"] == "fail"
    assert results["aws_iam_root_mfa"] == "pass"


def test_seed_mappings_populates_table(db):
    inserted = seed_mappings(db)
    assert inserted > 0
    assert db.query(ComplianceMapping).count() == inserted
    # Idempotent.
    assert seed_mappings(db) == 0


def test_every_mapping_uses_known_framework():
    from cspm.compliance.mappings import FRAMEWORKS

    for frameworks in SEED_MAPPINGS.values():
        for fw in frameworks:
            assert fw in FRAMEWORKS


# ---- drift -----------------------------------------------------------------
def test_drift_detects_created_and_deleted():
    baseline = {"sg:1": {"type": "security_group", "ingress": []}}
    current = {"s3:new": {"type": "s3_bucket"}}
    drifts = diff_snapshots(baseline, current)
    types = {(d.resource_id, d.drift_type) for d in drifts}
    assert ("s3:new", "created") in types
    assert ("sg:1", "deleted") in types


def test_drift_detects_permission_change():
    baseline = {"sg:1": {"type": "security_group", "ingress": [{"port": 443}]}}
    current = {"sg:1": {"type": "security_group", "ingress": [{"port": 22}]}}
    drifts = diff_snapshots(baseline, current)
    assert len(drifts) == 1
    assert drifts[0].drift_type == "permission_changed"
    assert drifts[0].security_sensitive


def test_drift_ignores_key_order():
    baseline = {"x:1": {"type": "config", "a": 1, "b": 2}}
    current = {"x:1": {"b": 2, "a": 1, "type": "config"}}
    assert diff_snapshots(baseline, current) == []


def test_security_sensitive_classification():
    assert is_security_sensitive("iam_policy")
    assert not is_security_sensitive("cloudwatch_dashboard")
