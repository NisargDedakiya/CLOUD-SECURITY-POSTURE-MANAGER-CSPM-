"""CSPM Celery tasks registered on the shared app (spec 2.3).

Audits run on the 'high' queue; scheduled drift checks on 'default', with a
security-sensitive drift hit re-routing an alert task to 'critical'.

The core logic lives in :mod:`cspm.service`; these are thin task wrappers so the
same behavior is available synchronously in dev/tests via ``.run_*`` helpers.
"""

from __future__ import annotations

from datetime import UTC

from cspm.celery_app import app
from cspm.db import SessionLocal
from cspm.drift.detector import is_security_sensitive
from cspm.models import CloudAccount
from cspm.service import run_audit, run_drift_check


def _run_aws_audit(cloud_account_id: str, scan_run_id: str | None = None) -> dict:
    from cspm.models import ScanRun

    db = SessionLocal()
    try:
        account = db.get(CloudAccount, cloud_account_id)
        if account is None:
            return {"error": "account_not_found"}
        scan = db.get(ScanRun, scan_run_id) if scan_run_id else None
        scan = run_audit(db, account, scan=scan)
        return {"scan_run_id": scan.id, "findings": scan.findings_count}
    finally:
        db.close()


def _run_drift_check(cloud_account_id: str) -> dict:
    db = SessionLocal()
    try:
        account = db.get(CloudAccount, cloud_account_id)
        if account is None:
            return {"error": "account_not_found"}
        events = run_drift_check(db, account)
        critical = [e for e in events if is_security_sensitive(e.resource_type)]
        # A sensitive drift hit re-routes an urgent alert onto the 'critical' queue.
        if critical and app is not None:  # pragma: no cover - needs broker
            for evt in critical:
                app.send_task(
                    "cspm.alert_drift", args=[evt.id], queue="critical"
                )
        return {"drift_events": len(events), "critical": len(critical)}
    finally:
        db.close()


def _scheduled_drift_sweep() -> dict:
    """Beat entry point: run a drift check for every active cloud account."""
    db = SessionLocal()
    try:
        accounts = db.query(CloudAccount).filter_by(status="active").all()
        for acct in accounts:
            if app is not None:  # pragma: no cover - needs broker
                app.send_task("cspm.run_drift_check", args=[acct.id], queue="default")
        return {"scheduled": len(accounts)}
    finally:
        db.close()


def _retention_purge() -> dict:
    """Delete data past the configured retention windows (GDPR/data residency)."""
    from datetime import datetime, timedelta

    from cspm.config import get_settings
    from cspm.models import FindingRecord
    from cspm.shared.models import AuditLogEntry

    s = get_settings()
    now = datetime.now(UTC)
    db = SessionLocal()
    try:
        f_cutoff = now - timedelta(days=s.findings_retention_days)
        a_cutoff = now - timedelta(days=s.audit_retention_days)
        findings = (
            db.query(FindingRecord)
            .filter(FindingRecord.status == "resolved", FindingRecord.resolved_at < f_cutoff)
            .delete(synchronize_session=False)
        )
        audits = (
            db.query(AuditLogEntry)
            .filter(AuditLogEntry.ts < a_cutoff)
            .delete(synchronize_session=False)
        )
        db.commit()
        return {"findings_purged": findings, "audit_purged": audits}
    finally:
        db.close()


if app is not None:  # pragma: no cover - requires celery/broker
    run_aws_audit = app.task(name="cspm.run_aws_audit", queue="high")(_run_aws_audit)
    run_drift_check_task = app.task(name="cspm.run_drift_check", queue="default")(
        _run_drift_check
    )
    scheduled_drift_sweep = app.task(name="cspm.scheduled_drift_sweep")(_scheduled_drift_sweep)
    retention_purge = app.task(name="cspm.retention_purge")(_retention_purge)
else:
    run_aws_audit = _run_aws_audit
    run_drift_check_task = _run_drift_check
    scheduled_drift_sweep = _scheduled_drift_sweep
    retention_purge = _retention_purge
