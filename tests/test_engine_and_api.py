"""Integration tests for the scan engine and the API."""

import pytest

from cspm.engine import ScanEngine
from cspm.models import Cloud


def test_engine_scans_all_clouds():
    result = ScanEngine().scan()
    assert result.resources_scanned > 0
    assert result.checks_run > 0
    assert result.finished_at is not None
    # There are intentionally-insecure mock resources, so we expect failures.
    assert len(result.failed) > 0


def test_engine_single_cloud():
    result = ScanEngine(clouds=[Cloud.AWS]).scan()
    assert all(f.cloud == Cloud.AWS for f in result.findings)


def test_summary_score_bounds():
    summary = ScanEngine().scan().summary()
    assert 0.0 <= summary["posture_score"] <= 100.0
    assert summary["total_findings"] == sum(summary["by_severity"].values())


def test_findings_sorted_failed_first():
    findings = ScanEngine().scan().findings
    passed_flags = [f.passed for f in findings]
    # Once a passed finding appears, no failed finding should follow.
    assert passed_flags == sorted(passed_flags)


api_deps = pytest.importorskip("fastapi")


def _client():
    from fastapi.testclient import TestClient

    from cspm.api.app import app

    return TestClient(app)


def test_api_health():
    resp = _client().get("/api/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_api_checks():
    data = _client().get("/api/checks").json()
    assert data["count"] > 0
    assert all("remediation" in c for c in data["checks"])


def test_api_scan():
    data = _client().get("/api/scan?cloud=aws").json()
    assert "summary" in data
    assert all(f["cloud"] == "aws" for f in data["findings"])


def test_api_scan_invalid_cloud():
    resp = _client().get("/api/scan?cloud=oracle")
    assert resp.status_code == 400
