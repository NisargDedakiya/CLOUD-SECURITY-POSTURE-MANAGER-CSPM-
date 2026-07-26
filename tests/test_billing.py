"""Tests for subscription plans, entitlements, and billing endpoints."""

from datetime import UTC

import pytest

from cspm.billing import PLANS, has_feature, plan_of, usage_summary
from cspm.billing.entitlements import (
    EntitlementError,
    check_account_limit,
    check_scan_quota,
    get_subscription,
)
from cspm.billing.plans import Feature
from cspm.billing.stripe_gateway import change_plan
from cspm.models import CloudAccount, ScanRun
from cspm.shared.models import Organisation


@pytest.fixture()
def free_org(db):
    o = Organisation(name="Free Co", slug="free-co")
    db.add(o)
    db.commit()
    db.refresh(o)
    return o  # no subscription row → defaults to free


def _add_accounts(db, org_id, n):
    for i in range(n):
        db.add(CloudAccount(org_id=org_id, provider="aws", role_arn=f"r{i}", status="active"))
    db.commit()


# ---- plan resolution -------------------------------------------------------
def test_defaults_to_free(db, free_org):
    assert plan_of(db, free_org.id).id == "free"
    assert get_subscription(db, free_org.id).plan == "free"


def test_free_plan_feature_gates(db, free_org):
    assert not has_feature(db, free_org.id, Feature.DRIFT)
    assert not has_feature(db, free_org.id, Feature.MULTI_CLOUD)


def test_change_plan_unlocks_features(db, free_org):
    change_plan(db, free_org.id, "pro")
    assert plan_of(db, free_org.id).id == "pro"
    assert has_feature(db, free_org.id, Feature.MULTI_CLOUD)
    assert has_feature(db, free_org.id, Feature.DRIFT)


def test_past_due_falls_back_to_free(db, free_org):
    change_plan(db, free_org.id, "pro", status="past_due")
    assert plan_of(db, free_org.id).id == "free"


# ---- limits ----------------------------------------------------------------
def test_account_limit_enforced(db, free_org):
    _add_accounts(db, free_org.id, 1)  # free allows 1
    with pytest.raises(EntitlementError):
        check_account_limit(db, free_org.id)


def test_account_limit_raised_on_upgrade(db, free_org):
    change_plan(db, free_org.id, "starter")  # 3 accounts
    _add_accounts(db, free_org.id, 2)
    check_account_limit(db, free_org.id)  # ok, under 3


def test_scan_quota_enforced(db, free_org):
    from datetime import datetime

    acct = CloudAccount(org_id=free_org.id, provider="aws", role_arn="r", status="active")
    db.add(acct)
    db.commit()
    db.refresh(acct)
    for _ in range(10):  # free allows 10/month
        db.add(ScanRun(cloud_account_id=acct.id, status="completed", started_at=datetime.now(UTC)))
    db.commit()
    with pytest.raises(EntitlementError):
        check_scan_quota(db, free_org.id)


def test_usage_summary_shape(db, free_org):
    u = usage_summary(db, free_org.id)
    assert u["plan"] == "free"
    assert u["accounts"]["limit"] == 1
    assert "scans_this_month" in u


def test_plan_catalog_serialization():
    from cspm.billing.plans import plan_public

    pub = plan_public(PLANS["pro"])
    assert pub["id"] == "pro"
    assert "multi_cloud" in pub["features"]
    assert pub["limits"]["max_accounts"] == 15


# ---- API (billing endpoints + gating) --------------------------------------
@pytest.fixture()
def free_client(db, free_org, monkeypatch):
    from fastapi.testclient import TestClient

    import cspm.api.router as router_mod
    from cspm.api.app import app
    from cspm.compliance import seed_mappings
    from cspm.connectors.aws import AWSConnector
    from cspm.fakes import FakeAWSSession
    from cspm.service import run_audit as real_run_audit

    app.dependency_overrides[router_mod.get_db] = lambda: db
    monkeypatch.setattr(router_mod, "run_audit",
                        lambda d, acct, **kw: real_run_audit(d, acct, session=FakeAWSSession()))
    real_get = router_mod.get_connector
    monkeypatch.setattr(router_mod, "get_connector",
                        lambda provider, **kw: AWSConnector(session=FakeAWSSession(), **kw) if provider == "aws" else real_get(provider, **kw))
    seed_mappings(db)
    c = TestClient(app)
    c.headers.update({"X-Org-Id": free_org.id, "X-Role": "admin", "X-User-Id": "u"})
    yield c
    app.dependency_overrides.clear()


def test_list_plans(free_client):
    r = free_client.get("/api/v1/cspm/billing/plans")
    assert r.status_code == 200
    body = r.json()
    assert body["current_plan"] == "free"
    assert {p["id"] for p in body["plans"]} == {"free", "starter", "pro", "enterprise"}


def test_free_org_blocked_from_second_account(free_client):
    a1 = free_client.post("/api/v1/cspm/accounts", json={"provider": "aws", "role_arn": "arn:1"})
    assert a1.status_code == 201
    a2 = free_client.post("/api/v1/cspm/accounts", json={"provider": "aws", "role_arn": "arn:2"})
    assert a2.status_code == 402
    assert a2.json()["upgrade_to"]


def test_free_org_blocked_from_gcp(free_client):
    r = free_client.post("/api/v1/cspm/accounts", json={"provider": "gcp", "service_account_json": "{}"})
    assert r.status_code == 402


def test_free_org_blocked_from_drift_and_evidence(free_client):
    assert free_client.get("/api/v1/cspm/drift").status_code == 402
    assert free_client.get("/api/v1/cspm/compliance/soc2").status_code == 402  # framework gated


def test_checkout_manual_mode_upgrades(free_client):
    r = free_client.post("/api/v1/cspm/billing/checkout", json={"plan": "pro"})
    assert r.status_code == 200
    assert r.json()["plan"] == "pro"
    # Now multi-cloud + drift are unlocked.
    assert free_client.get("/api/v1/cspm/drift").status_code == 200


def test_upgrade_then_second_account_allowed(free_client):
    free_client.post("/api/v1/cspm/billing/checkout", json={"plan": "pro"})
    free_client.post("/api/v1/cspm/accounts", json={"provider": "aws", "role_arn": "arn:1"})
    r = free_client.post("/api/v1/cspm/accounts", json={"provider": "aws", "role_arn": "arn:2"})
    assert r.status_code == 201


def test_trial_unlocks_pro_then_expires(db, free_org):
    from datetime import datetime, timedelta

    from cspm.billing.entitlements import get_subscription, plan_of, start_trial

    start_trial(db, free_org.id)
    assert plan_of(db, free_org.id).id == "pro"  # trial active → Pro features

    # Force expiry → reverts to free on next resolution.
    sub = get_subscription(db, free_org.id)
    sub.trial_ends_at = datetime.now(UTC) - timedelta(days=1)
    db.commit()
    assert plan_of(db, free_org.id).id == "free"


def test_trial_is_one_time(db, free_org):
    from cspm.billing.entitlements import EntitlementError, start_trial

    start_trial(db, free_org.id)
    with pytest.raises(EntitlementError):
        start_trial(db, free_org.id)


def test_trial_endpoint_flow(free_client):
    r = free_client.post("/api/v1/cspm/billing/trial", json={"plan": "pro"})
    assert r.status_code == 200
    assert r.json()["status"] == "trialing"
    sub = free_client.get("/api/v1/cspm/billing/subscription").json()
    assert sub["plan"] == "pro" and sub["trial_days_left"] >= 13
    # Pro features now work during the trial.
    assert free_client.get("/api/v1/cspm/drift").status_code == 200
    # Trial can't be started twice.
    assert free_client.post("/api/v1/cspm/billing/trial", json={"plan": "pro"}).status_code == 402


def test_prowler_ingest_gated_and_works(free_client):
    acct_id = free_client.post(
        "/api/v1/cspm/accounts", json={"provider": "aws", "role_arn": "arn:1"}
    ).json()["id"]
    prowler_results = {
        "results": [
            {"status": "FAIL", "check_id": "iam_root_mfa", "severity": "critical",
             "resource_uid": "arn:aws:iam::1:root", "check_title": "Root MFA"},
            {"status": "FAIL", "check_id": "ec2_ebs_encryption", "severity": "high",
             "resource_uid": "vol-1", "check_title": "EBS encryption"},
        ]
    }
    # Free plan: Prowler is gated.
    blocked = free_client.post(f"/api/v1/cspm/accounts/{acct_id}/prowler-ingest", json=prowler_results)
    assert blocked.status_code == 402

    # Upgrade to Pro → ingestion works.
    free_client.post("/api/v1/cspm/billing/checkout", json={"plan": "pro"})
    ok = free_client.post(f"/api/v1/cspm/accounts/{acct_id}/prowler-ingest", json=prowler_results)
    assert ok.status_code == 202
    assert ok.json()["findings_count"] == 2
    ids = {f["check_id"] for f in free_client.get("/api/v1/cspm/findings").json()}
    assert "prowler_iam_root_mfa" in ids
