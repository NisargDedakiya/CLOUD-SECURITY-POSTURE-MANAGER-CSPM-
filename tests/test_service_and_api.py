"""Integration tests for the service layer and the FastAPI router."""

import pytest

from cspm.fakes import FakeAWSSession
from cspm.models import Baseline, CloudAccount, FindingRecord
from cspm.service import run_audit, run_drift_check


@pytest.fixture()
def aws_account(db, org):
    acct = CloudAccount(
        org_id=org.id,
        provider="aws",
        label="prod",
        role_arn="arn:aws:iam::123:role/audit",
        external_id="ext-1",
        status="active",
    )
    db.add(acct)
    db.commit()
    db.refresh(acct)
    return acct


def test_run_audit_persists_findings(db, aws_account):
    scan = run_audit(db, aws_account, session=FakeAWSSession())
    assert scan.status == "completed"
    assert scan.findings_count > 0
    stored = db.query(FindingRecord).filter_by(scan_run_id=scan.id).count()
    assert stored == scan.findings_count


def test_run_audit_dedups_across_runs(db, aws_account):
    run_audit(db, aws_account, session=FakeAWSSession())
    total_after_first = db.query(FindingRecord).count()
    run_audit(db, aws_account, session=FakeAWSSession())
    # Same findings → dedup_hash prevents duplicates.
    assert db.query(FindingRecord).count() == total_after_first


def test_drift_first_run_sets_baseline(db, aws_account):
    events = run_drift_check(db, aws_account, session=FakeAWSSession())
    assert events == []
    assert db.query(Baseline).filter_by(cloud_account_id=aws_account.id).count() > 0


# ---- API -------------------------------------------------------------------
pytest.importorskip("fastapi")


@pytest.fixture()
def client(db, org, monkeypatch):
    from fastapi.testclient import TestClient

    import cspm.api.router as router_mod
    from cspm.api.app import app
    from cspm.connectors.aws import AWSConnector
    from cspm.service import run_audit as real_run_audit

    # Route the request-scoped DB and the audit's boto3 session at the test doubles.
    app.dependency_overrides[router_mod.get_db] = lambda: db
    monkeypatch.setattr(
        router_mod, "run_audit",
        lambda d, acct: real_run_audit(d, acct, session=FakeAWSSession()),
    )

    # Make AWS connector validation use the fake session (no live AssumeRole).
    real_get_connector = router_mod.get_connector

    def _fake_get_connector(provider, **kwargs):
        if provider == "aws":
            return AWSConnector(session=FakeAWSSession(), **kwargs)
        return real_get_connector(provider, **kwargs)

    monkeypatch.setattr(router_mod, "get_connector", _fake_get_connector)
    from cspm.compliance import seed_mappings

    seed_mappings(db)
    c = TestClient(app)
    c.headers.update({"X-Org-Id": org.id, "X-User-Id": "u1"})
    yield c
    app.dependency_overrides.clear()


def _connect_aws(client):
    return client.post(
        "/api/v1/cspm/accounts",
        json={"provider": "aws", "label": "prod", "role_arn": "arn:aws:iam::1:role/a"},
    )


def test_health(client):
    r = client.get("/api/v1/cspm/health")
    assert r.status_code == 200
    assert "frameworks" in r.json()


def test_requires_org_header(client):
    r = client.get("/api/v1/cspm/accounts", headers={"X-Org-Id": ""})
    assert r.status_code == 401


def test_connect_account_hides_secrets(client):
    r = _connect_aws(client)
    assert r.status_code == 201
    body = r.json()
    assert body["provider"] == "aws"
    assert "role_arn" not in body and "external_id" not in body


def test_full_scan_and_findings_flow(client):
    acct_id = _connect_aws(client).json()["id"]
    scan = client.post(f"/api/v1/cspm/accounts/{acct_id}/scan")
    assert scan.status_code == 202
    assert scan.json()["findings_count"] > 0

    findings = client.get("/api/v1/cspm/findings").json()
    assert findings
    crit = client.get("/api/v1/cspm/findings?severity=critical").json()
    assert all(f["severity"] == "critical" for f in crit)

    # Update a finding status.
    fid = findings[0]["id"]
    upd = client.patch(f"/api/v1/cspm/findings/{fid}", json={"status": "resolved"})
    assert upd.status_code == 200 and upd.json()["status"] == "resolved"


def test_compliance_endpoints(client):
    acct_id = _connect_aws(client).json()["id"]
    client.post(f"/api/v1/cspm/accounts/{acct_id}/scan")
    score = client.get("/api/v1/cspm/compliance/cis_aws_v2")
    assert score.status_code == 200
    assert score.json()["score"] < 100.0
    evidence = client.get("/api/v1/cspm/compliance/cis_aws_v2/evidence")
    assert evidence.status_code == 200 and evidence.json()["controls"]
    assert client.get("/api/v1/cspm/compliance/nope").status_code == 404


def test_org_isolation(client, db):
    """An account in another org must not be visible."""
    other = CloudAccount(org_id="other-org", provider="aws", role_arn="x", status="active")
    db.add(other)
    db.commit()
    # Not found because it's scoped to a different org.
    assert client.post(f"/api/v1/cspm/accounts/{other.id}/scan").status_code == 404


def test_disconnect_account(client):
    acct_id = _connect_aws(client).json()["id"]
    assert client.delete(f"/api/v1/cspm/accounts/{acct_id}").status_code == 204
    assert client.get("/api/v1/cspm/accounts").json() == []
