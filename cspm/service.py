"""Service layer: orchestrates audits, persistence, and drift.

Shared by the FastAPI router (synchronous path for dev/tests) and the Celery
tasks (async path in production). Keeping this logic here means both entry
points behave identically.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy.orm import Session

from cspm.auditors.aws import AWSAuditor
from cspm.auditors.base import BaseAuditor
from cspm.auditors.findings import Finding
from cspm.drift.detector import diff_snapshots
from cspm.models import (
    Baseline,
    CloudAccount,
    DriftEvent,
    FindingRecord,
    ScanRun,
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def build_auditor(account: CloudAccount, session=None) -> BaseAuditor:
    """Construct the right auditor for a connected account.

    ``session`` (a boto3/fake session) can be injected for AWS to avoid a live
    AssumeRole — used by tests and by callers that already hold a session.
    """
    if account.provider == "aws":
        return AWSAuditor(
            role_arn=account.role_arn,
            external_id=account.external_id,
            session=session,
        )
    raise NotImplementedError(
        f"Auditor for provider '{account.provider}' is a follow-on (spec Step 5)."
    )


def run_audit(
    db: Session, account: CloudAccount, session=None
) -> ScanRun:
    """Run all checks for an account, persisting a scan run and its findings."""
    scan = ScanRun(
        cloud_account_id=account.id, status="running", started_at=_now()
    )
    db.add(scan)
    db.flush()

    auditor = build_auditor(account, session=session)
    findings: list[Finding] = auditor.run_all()

    persisted = 0
    for f in findings:
        dedup = f.dedup_hash(account.id)
        existing = (
            db.query(FindingRecord).filter_by(dedup_hash=dedup).one_or_none()
        )
        if existing is not None:
            continue
        db.add(
            FindingRecord(
                org_id=account.org_id,
                cloud_account_id=account.id,
                scan_run_id=scan.id,
                check_id=f.check_id,
                resource=f.resource,
                severity=f.severity,
                description=f.description,
                remediation=f.remediation,
                dedup_hash=dedup,
            )
        )
        persisted += 1

    scan.status = "completed"
    scan.completed_at = _now()
    scan.checks_run = len(auditor.list_checks())
    scan.findings_count = persisted
    db.commit()
    db.refresh(scan)
    return scan


def run_drift_check(
    db: Session, account: CloudAccount, session=None
) -> list[DriftEvent]:
    """Compare current config to the approved baseline; record drift events.

    First run establishes the baseline and emits no drift (spec 6.4).
    """
    auditor = build_auditor(account, session=session)
    current = auditor.resource_snapshots()

    existing = (
        db.query(Baseline).filter_by(cloud_account_id=account.id).all()
    )
    if not existing:
        for rid, cfg in current.items():
            db.add(
                Baseline(
                    cloud_account_id=account.id,
                    resource_type=cfg.get("type"),
                    resource_id=rid,
                    config_snapshot=cfg,
                )
            )
        db.commit()
        return []

    baseline = {b.resource_id: b.config_snapshot for b in existing}
    events: list[DriftEvent] = []
    for d in diff_snapshots(baseline, current):
        evt = DriftEvent(
            org_id=account.org_id,
            cloud_account_id=account.id,
            resource_type=d.resource_type,
            resource_id=d.resource_id,
            drift_type=d.drift_type,
            before_state=d.before_state,
            after_state=d.after_state,
        )
        db.add(evt)
        events.append(evt)
    db.commit()
    return events
