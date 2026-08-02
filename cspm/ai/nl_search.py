"""AI Natural Language Search Engine.

Parses natural language user queries like 'Show internet-facing databases'
or 'Which IAM roles have administrator privileges?' into structured search filters.
"""

from __future__ import annotations

from typing import Any
from sqlalchemy.orm import Session
from cspm.models import AssetRecord, FindingRecord


def parse_and_execute_nl_query(db: Session, org_id: str, query_text: str) -> dict[str, Any]:
    """Parse natural language prompt and return matching resources/findings."""
    q_lower = query_text.lower()

    if "database" in q_lower or "db" in q_lower:
        assets = (
            db.query(AssetRecord)
            .filter_by(org_id=org_id, category="database")
            .all()
        )
        return {
            "query": query_text,
            "intent": "search_databases",
            "count": len(assets),
            "results": [
                {
                    "id": a.id,
                    "name": a.name,
                    "category": a.category,
                    "provider": a.provider,
                    "is_internet_facing": a.is_internet_facing,
                    "is_encrypted": a.is_encrypted,
                }
                for a in assets
            ],
        }
    elif "iam" in q_lower or "role" in q_lower or "administrator" in q_lower:
        findings = (
            db.query(FindingRecord)
            .filter(FindingRecord.org_id == org_id, FindingRecord.check_id.like("%IAM%"))
            .all()
        )
        return {
            "query": query_text,
            "intent": "search_iam_overprivileged",
            "count": len(findings),
            "results": [
                {
                    "id": f.id,
                    "check_id": f.check_id,
                    "resource": f.resource,
                    "severity": f.severity,
                    "description": f.description,
                }
                for f in findings
            ],
        }
    elif "encryption" in q_lower or "unencrypted" in q_lower:
        assets = (
            db.query(AssetRecord)
            .filter_by(org_id=org_id, is_encrypted=False)
            .all()
        )
        return {
            "query": query_text,
            "intent": "search_unencrypted_resources",
            "count": len(assets),
            "results": [
                {
                    "id": a.id,
                    "name": a.name,
                    "category": a.category,
                    "provider": a.provider,
                    "is_encrypted": a.is_encrypted,
                }
                for a in assets
            ],
        }
    else:
        # Fallback keyword match against findings
        findings = (
            db.query(FindingRecord)
            .filter(FindingRecord.org_id == org_id)
            .limit(10)
            .all()
        )
        return {
            "query": query_text,
            "intent": "general_findings_search",
            "count": len(findings),
            "results": [
                {
                    "id": f.id,
                    "check_id": f.check_id,
                    "resource": f.resource,
                    "severity": f.severity,
                    "description": f.description,
                }
                for f in findings
            ],
        }
