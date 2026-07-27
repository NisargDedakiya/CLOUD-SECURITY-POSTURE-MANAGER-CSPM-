"""Tests for production-hardening: config guards, RBAC, pagination, audit log,
multi-cloud auditors."""

import importlib

import pytest

from cspm.auditors.azure import AzureAuditor
from cspm.auditors.gcp import GCPAuditor
from cspm.fakes import FakeAzureCollector, FakeGCPCollector


# ---- config guards ---------------------------------------------------------
def test_production_requires_encryption_key(monkeypatch):
    import cspm.config as cfg

    monkeypatch.setenv("CSPM_ENV", "production")
    monkeypatch.setenv("CSPM_DATABASE_URL", "postgresql+psycopg://u:p@h/db")
    monkeypatch.setenv("CSPM_EAGER_TASKS", "false")
    monkeypatch.delenv("CSPM_ENCRYPTION_KEY", raising=False)
    importlib.reload(cfg)
    with pytest.raises(cfg.ConfigError):
        cfg.Settings()


def test_development_has_safe_defaults(monkeypatch):
    import cspm.config as cfg

    for var in ("CSPM_ENV", "CSPM_DATABASE_URL", "CSPM_EAGER_TASKS", "CSPM_ENCRYPTION_KEY"):
        monkeypatch.delenv(var, raising=False)
    importlib.reload(cfg)
    s = cfg.Settings()
    assert not s.is_production
    assert s.eager_tasks is True


# ---- multi-cloud auditors --------------------------------------------------
def test_gcp_auditor_flags_public_bucket():
    findings = GCPAuditor(collector=FakeGCPCollector()).run_all()
    ids = {f.check_id for f in findings}
    assert {"gcp_bucket_public", "gcp_firewall_open", "gcp_sa_key_age",
            "gcp_sql_public_ip", "gcp_audit_logging"} <= ids
    assert not any(f.check_id.endswith("_error") for f in findings)


def test_azure_auditor_flags_public_blob():
    findings = AzureAuditor(collector=FakeAzureCollector()).run_all()
    ids = {f.check_id for f in findings}
    assert {"azure_storage_public_blob", "azure_nsg_open_mgmt", "azure_vm_disk_encryption",
            "azure_storage_min_tls", "azure_keyvault_protection"} <= ids
    assert not any(f.check_id.endswith("_error") for f in findings)


def test_gcp_secure_bucket_not_flagged():
    findings = GCPAuditor(collector=FakeGCPCollector()).check_bucket_public_access()
    assert all("internal" not in f.resource for f in findings)


# ---- RBAC + pagination + audit (via API) -----------------------------------
@pytest.fixture()
def client(db, org, monkeypatch):
    from fastapi.testclient import TestClient

    import cspm.api.router as router_mod
    from cspm.api.app import app
    from cspm.compliance import seed_mappings
    from cspm.connectors.aws import AWSConnector
    from cspm.fakes import FakeAWSSession
    from cspm.service import run_audit as real_run_audit

    app.dependency_overrides[router_mod.get_db] = lambda: db
    monkeypatch.setattr(
        router_mod, "run_audit",
        lambda d, acct, **kw: real_run_audit(d, acct, session=FakeAWSSession()),
    )
    real_get_connector = router_mod.get_connector

    def _fake_get_connector(provider, **kwargs):
        if provider == "aws":
            return AWSConnector(session=FakeAWSSession(), **kwargs)
        return real_get_connector(provider, **kwargs)

    monkeypatch.setattr(router_mod, "get_connector", _fake_get_connector)
    seed_mappings(db)
    c = TestClient(app)
    c.headers.update({"X-Org-Id": org.id, "X-User-Id": "u1"})
    yield c
    app.dependency_overrides.clear()


def _connect(client, role="admin"):
    return client.post(
        "/api/v1/cspm/accounts",
        json={"provider": "aws", "label": "p", "role_arn": "arn:aws:iam::1:role/a"},
        headers={"X-Role": role},
    )


def test_viewer_cannot_connect(client):
    r = _connect(client, role="viewer")
    assert r.status_code == 403


def test_analyst_can_connect_but_not_delete(client):
    acct = _connect(client, role="analyst")
    assert acct.status_code == 201
    acct_id = acct.json()["id"]
    # analyst may not delete (admin only)
    assert client.delete(
        f"/api/v1/cspm/accounts/{acct_id}", headers={"X-Role": "analyst"}
    ).status_code == 403
    assert client.delete(
        f"/api/v1/cspm/accounts/{acct_id}", headers={"X-Role": "admin"}
    ).status_code == 204


def test_audit_log_records_actions(client, db):
    from cspm.shared.models import AuditLogEntry

    _connect(client)
    actions = {a.action for a in db.query(AuditLogEntry).all()}
    assert "cspm.account.connect" in actions


def test_pagination_sets_total_count(client):
    _connect(client)
    acct_id = client.get("/api/v1/cspm/accounts").json()[0]["id"]
    client.post(f"/api/v1/cspm/accounts/{acct_id}/scan")
    r = client.get("/api/v1/cspm/findings?limit=3")
    assert r.status_code == 200
    assert len(r.json()) <= 3
    assert int(r.headers["X-Total-Count"]) >= len(r.json())


def test_ready_probe(client):
    assert client.get("/api/v1/cspm/ready").json()["status"] == "ready"


def test_dev_seed_populates_dashboard(client):
    r = client.post("/api/v1/cspm/dev/seed")
    assert r.status_code == 201
    assert r.json()["findings"] > 0
    # Dashboard data is now available.
    assert client.get("/api/v1/cspm/accounts").json()
    assert client.get("/api/v1/cspm/findings").json()
    trend = client.get("/api/v1/cspm/compliance/cis_aws_v2/trend").json()
    assert trend["series"]  # a snapshot was recorded


def test_remediation_endpoint(client):
    client.post("/api/v1/cspm/dev/seed")
    fid = client.get("/api/v1/cspm/findings").json()[0]["id"]
    r = client.get(f"/api/v1/cspm/findings/{fid}/remediation")
    assert r.status_code == 200
    assert "snippets" in r.json()


def test_audit_verify_endpoint(client):
    client.post("/api/v1/cspm/dev/seed")
    r = client.get("/api/v1/cspm/audit/verify")
    assert r.status_code == 200 and r.json()["intact"] is True


def test_aws_prepare_returns_external_id_and_launch_url(client):
    r = client.post("/api/v1/cspm/accounts/aws/prepare")
    assert r.status_code == 200
    body = r.json()
    assert len(body["external_id"]) >= 8
    assert body["external_id"] in body["launch_stack_url"]
    assert "cloudformation" in body["launch_stack_url"]
    # Each call mints a fresh id.
    assert client.post("/api/v1/cspm/accounts/aws/prepare").json()["external_id"] != body["external_id"]
