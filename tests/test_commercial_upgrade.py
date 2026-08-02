"""Test suite for Aegis Commercial Enterprise Upgrade modules."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from cspm.api.app import app
from cspm.compliance.mappings import FRAMEWORKS
from cspm.engine.knowledge_graph import build_cloud_knowledge_graph, get_hierarchical_asset_tree
from cspm.engine.runtime_cdr import get_runtime_cdr_events
from cspm.integrations.siem import dispatch_siem_stream, format_siem_event


def test_knowledge_graph(db, org):
    graph = build_cloud_knowledge_graph(db, org.id)
    assert graph["nodes_count"] >= 1
    assert "max_blast_radius" in graph


def test_asset_hierarchy_tree(db, org):
    tree = get_hierarchical_asset_tree(db, org.id)
    assert "children" in tree
    assert len(tree["children"]) >= 3


def test_runtime_cdr_engine(db, org):
    events = get_runtime_cdr_events(db, org.id)
    assert len(events) >= 3
    assert any(e["event_type"] == "container_runtime_threat" for e in events)


def test_siem_dispatcher():
    finding = {"check_id": "AWS-S3-001", "severity": "critical", "resource": "my-bucket", "description": "Public bucket"}
    log = format_siem_event(finding, "splunk")
    assert log["source"] == "aegis:security:alert"

    res = dispatch_siem_stream([finding], "splunk")
    assert res["status"] == "success"
    assert res["logs_streamed_count"] == 1


def test_extended_compliance_frameworks():
    assert "fedramp_high" in FRAMEWORKS
    assert "gdpr" in FRAMEWORKS
    assert "dora" in FRAMEWORKS
    assert "nis2" in FRAMEWORKS
    assert "csa_ccm" in FRAMEWORKS


def test_commercial_api_endpoints():
    client = TestClient(app)
    headers = {"X-Org-Id": "demo-org", "X-Role": "admin"}

    res = client.get("/api/v1/cspm/knowledge-graph", headers=headers)
    assert res.status_code == 200

    res = client.get("/api/v1/cspm/asset-hierarchy", headers=headers)
    assert res.status_code == 200

    res = client.get("/api/v1/cspm/runtime/events", headers=headers)
    assert res.status_code == 200

    res = client.post("/api/v1/cspm/siem/export", json={"siem_provider": "splunk"}, headers=headers)
    assert res.status_code == 200
