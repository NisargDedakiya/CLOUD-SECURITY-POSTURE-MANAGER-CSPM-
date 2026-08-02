"""Unified AI Security Copilot Engine.

Merges remediation suggestions, executive summaries, risk prioritization,
and natural language query parsing into a single conversational assistant.
"""

from __future__ import annotations

from typing import Any
from sqlalchemy.orm import Session
from cspm.ai.nl_search import parse_and_execute_nl_query
from cspm.ai.prioritization import calculate_dynamic_risk_score
from cspm.ai.remediation import generate_ai_remediation
from cspm.ai.summary import generate_executive_ai_summary


def handle_copilot_chat(
    query: str,
    org_id: str,
    db: Session,
    check_id: str | None = None,
    resource_id: str | None = None,
) -> dict[str, Any]:
    """Process natural language queries and provide conversational security answers."""
    query_lower = query.lower()

    # Case 1: Executive Summary request
    if any(k in query_lower for k in ("summary", "executive", "report", "health", "posture")):
        summary = generate_executive_ai_summary(db, org_id)
        return {
            "intent": "executive_summary",
            "reply": f"Here is the AI Posture Summary for Organization '{org_id}':\n\n{summary['summary_text']}",
            "data": summary,
            "suggested_actions": ["Download PDF Executive Report", "View Top 5 Critical Risks"],
        }


    # Case 2: Prioritization / What to fix first
    if any(k in query_lower for k in ("first", "prioritize", "top risk", "critical")):
        risk = calculate_dynamic_risk_score({"severity": "critical", "is_internet_facing": True, "on_attack_path": True})
        return {
            "intent": "prioritization",
            "reply": f"AI Risk Engine calculated priority risk score {risk['score']}/10 ({risk['label']}). Focus on internet-facing resources with attack path vectors first.",
            "data": risk,
            "suggested_actions": ["View Attack Path Graph", "Export Remediation Backlog"],
        }

    # Case 3: Remediation / Fix request
    if any(k in query_lower for k in ("fix", "remediate", "terraform", "cli", "how do i", "how to")):
        target_check = check_id or "AWS-S3-001"
        target_res = resource_id or "arn:aws:s3:::customer-pii-backups"
        fix = generate_ai_remediation(target_check, target_res)
        return {
            "intent": "remediation_fix",
            "reply": f"AI Remediation for {target_check}:\n\n{fix['explanation']}\n\n**AWS CLI Command:**\n`{fix['cli_fix']}`\n\n**Terraform Code:**\n```hcl\n{fix['terraform_fix']}\n```",
            "data": fix,
            "suggested_actions": ["Apply Auto-Remediation", "Export Terraform Patch"],
        }



    # Case 4: Natural Language Search Query
    search_res = parse_and_execute_nl_query(db, org_id, query)
    return {
        "intent": search_res["intent"],
        "reply": f"Found {search_res['count']} resources matching your natural language query: '{query}'.",
        "data": search_res["results"],
        "suggested_actions": ["Filter Asset Explorer", "Export Search Results CSV"],
    }

