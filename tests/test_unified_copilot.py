"""Test suite for Unified AI Security Copilot Assistant."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from cspm.ai.unified_copilot import handle_copilot_chat
from cspm.api.app import app


def test_copilot_chat_engine(db, org):
    # Test executive summary query
    res = handle_copilot_chat("Show executive summary report", org.id, db)
    assert res["intent"] == "executive_summary"
    assert "summary_text" in res["data"]

    # Test remediation query
    res = handle_copilot_chat("How do I fix AWS-S3-001 with terraform?", org.id, db)
    assert res["intent"] == "remediation_fix"
    assert "terraform_fix" in res["data"]

    # Test prioritization query
    res = handle_copilot_chat("Which findings should I fix first?", org.id, db)
    assert res["intent"] == "prioritization"


def test_copilot_chat_endpoint():
    client = TestClient(app)
    headers = {"X-Org-Id": "demo-org", "X-Role": "admin"}

    res = client.post(
        "/api/v1/cspm/ai/copilot/chat",
        json={"query": "Explain how to remediate public S3 bucket"},
        headers=headers,
    )
    assert res.status_code == 200
    data = res.json()
    assert "reply" in data
    assert "intent" in data
