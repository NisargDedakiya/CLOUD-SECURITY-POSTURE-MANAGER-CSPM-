"""Test suite for Aegis Enterprise SaaS modules & endpoints."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from cspm.api.app import app
from cspm.engine.dashboard_metrics import get_executive_dashboard_metrics
from cspm.engine.iam_explorer import get_iam_explorer_data


def test_iam_explorer_engine(db, org):
    res = get_iam_explorer_data(db, org.id)
    assert res["roles_count"] >= 1
    assert res["users_count"] >= 1
    assert "privilege_escalations" in res


def test_dashboard_metrics_engine(db, org):
    res = get_executive_dashboard_metrics(db, org.id)
    assert res["overall_security_score"] == 91.5
    assert "cloud_scores" in res
    assert "scheduled_scans" in res


def test_enterprise_saas_endpoints():
    client = TestClient(app)
    headers = {"X-Org-Id": "demo-org", "X-Role": "admin"}

    res = client.get("/api/v1/cspm/iam-explorer", headers=headers)
    assert res.status_code == 200

    res = client.get("/api/v1/cspm/dashboard/metrics", headers=headers)
    assert res.status_code == 200

    res = client.get("/api/v1/cspm/organization/members", headers=headers)
    assert res.status_code == 200

    res = client.post("/api/v1/cspm/organization/settings", json={"name": "Updated Org"}, headers=headers)
    assert res.status_code == 200
