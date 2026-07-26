"""Reporting: CSV export and compliance trend series.

CSV is generated in-process (no external service). Trend series come from the
per-scan :class:`ComplianceSnapshot` rows recorded by the audit service, so a
dashboard can plot posture over time.
"""

from __future__ import annotations

import csv
import io

from sqlalchemy.orm import Session

from cspm.models import ComplianceSnapshot, FindingRecord


def findings_csv(db: Session, org_id: str) -> str:
    """Return all findings for an org as CSV text."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(
        ["check_id", "severity", "status", "resource", "description", "remediation", "discovered_at"]
    )
    rows = (
        db.query(FindingRecord)
        .filter_by(org_id=org_id)
        .order_by(FindingRecord.discovered_at.desc())
        .all()
    )
    for f in rows:
        writer.writerow(
            [
                f.check_id,
                f.severity,
                f.status,
                f.resource,
                f.description,
                f.remediation,
                f.discovered_at.isoformat() if f.discovered_at else "",
            ]
        )
    return buf.getvalue()


def compliance_trend(db: Session, org_id: str, framework: str, limit: int = 90) -> list[dict]:
    """Time series of compliance score for a framework (oldest → newest)."""
    rows = (
        db.query(ComplianceSnapshot)
        .filter_by(org_id=org_id, framework=framework)
        .order_by(ComplianceSnapshot.captured_at.desc())
        .limit(limit)
        .all()
    )
    return [
        {
            "captured_at": s.captured_at.isoformat() if s.captured_at else None,
            "score": s.score,
            "checks_passed": s.checks_passed,
            "checks_applicable": s.checks_applicable,
        }
        for s in reversed(rows)
    ]
