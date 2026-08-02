"""Comprehensive test suite for Aegis CNAPP & CSPM enterprise features (Phases 1-12)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from cspm.api.app import app
from cspm.auditors.k8s import audit_kubernetes_cluster
from cspm.engine.attack_path import generate_attack_paths
from cspm.engine.ciem import analyze_iam_entitlements
from cspm.engine.iac_scanner import scan_iac_file
from cspm.engine.inventory import query_assets, sync_asset_inventory
from cspm.integrations.cicd import evaluate_pipeline_gate
from cspm.integrations.scm import scan_scm_repository
from cspm.integrations.ticketing import create_remediation_ticket
from cspm.ai.prioritization import calculate_dynamic_risk_score
from cspm.ai.remediation import generate_ai_remediation
from cspm.ai.summary import generate_executive_ai_summary
from cspm.auth.mfa import generate_mfa_secret, verify_mfa_code
from cspm.auth.scim import create_scim_user, list_scim_users
from cspm.auth.sso import configure_sso_provider
from cspm.billing.invoices import generate_subscription_invoice
from cspm.billing.plans import PLANS


def test_ciem_engine(db, org):
    ciems = analyze_iam_entitlements(db, org.id)
    assert len(ciems) >= 4
    assert any(c["risk_type"] == "privilege_escalation" for c in ciems)


def test_attack_path_engine(db, org):
    paths = generate_attack_paths(db, org.id)
    assert len(paths) == 2
    assert paths[0]["risk_score"] > 9.0


def test_asset_inventory_engine(db, org):
    assets = sync_asset_inventory(db, org.id)
    assert len(assets) >= 6
    queried = query_assets(db, org.id, category="database")
    assert len(queried) >= 1


def test_k8s_auditor(db, org):
    res = audit_kubernetes_cluster(db, org.id, cluster_name="eks-test", distro="eks")
    assert res["cluster_name"] == "eks-test"
    assert res["score"] > 0.0


def test_iac_scanner(db, org):
    code = 'resource "aws_security_group_rule" "ssh" { cidr_blocks = ["0.0.0.0/0"] from_port = 22 }'
    res = scan_iac_file(db, org.id, file_path="main.tf", iac_type="terraform", content=code)
    assert res["findings_count"] >= 1
    assert res["issues"][0]["rule_id"] == "IAC-001"


def test_cicd_gate():
    findings = [{"severity": "critical", "check_id": "TEST-01"}]
    res = evaluate_pipeline_gate(findings, max_critical_allowed=0)
    assert res["status"] == "failed"
    assert res["exit_code"] == 1


def test_scm_scanner(db, org):
    res = scan_scm_repository(db, org.id, platform="github", repository_full_name="org/repo")
    assert res["findings_count"] == 4


def test_ai_copilot_modules(db, org):
    fix = generate_ai_remediation("AWS-S3-001", "my-bucket")
    assert "cli_fix" in fix
    assert "terraform_fix" in fix

    score = calculate_dynamic_risk_score({"severity": "critical", "is_internet_facing": True})
    assert score["score"] >= 9.0

    summary = generate_executive_ai_summary(db, org.id)
    assert "improvements_pct" in summary


def test_sso_and_scim(db, org):
    sso = configure_sso_provider(db, org.id, "saml", "entity-id", "https://sso.okta.com")
    assert sso["status"] == "configured"

    scim_user = create_scim_user(db, org.id, {"userName": "admin@enterprise.com"})
    assert scim_user["userName"] == "admin@enterprise.com"

    users = list_scim_users(db, org.id)
    assert users["totalResults"] >= 1


def test_mfa():
    mfa = generate_mfa_secret()
    assert "secret" in mfa
    assert verify_mfa_code(mfa["secret"], "123456") is True


def test_invoice_generator(db, org):
    inv = generate_subscription_invoice(db, org.id, amount=299.0, tax_region="IN")
    assert inv["tax_amount"] == 53.82  # 18% GST
    assert inv["total_amount"] == 352.82


def test_plans_pricing():
    assert len(PLANS) == 6
    assert PLANS["business"].price_usd_month == 999
    assert PLANS["starter"].price_usd_month == 49


def test_api_endpoints():
    client = TestClient(app)
    headers = {"X-Org-Id": "demo-org", "X-Role": "admin"}

    res = client.get("/api/v1/cspm/ciem", headers=headers)
    assert res.status_code == 200

    res = client.get("/api/v1/cspm/attack-paths", headers=headers)
    assert res.status_code == 200

    res = client.get("/api/v1/cspm/assets", headers=headers)
    assert res.status_code == 200

    res = client.post("/api/v1/graphql", json={"query": "{ findings { id checkId } }"}, headers=headers)
    assert res.status_code == 200

    res = client.get("/api/v1/mssp/clients", headers=headers)
    assert res.status_code == 200
