"""CSPM Celery tasks registered on the shared app (spec 2.3).

Audits run on the 'high' queue; scheduled drift checks on 'default', with a
security-sensitive drift hit re-routing an alert task to 'critical'.

The core logic lives in :mod:`cspm.service`; these are thin task wrappers so the
same behavior is available synchronously in dev/tests via ``.run_*`` helpers.
"""

from __future__ import annotations

from cspm.celery_app import app
from cspm.db import SessionLocal
from cspm.drift.detector import is_security_sensitive
from cspm.models import CloudAccount
from cspm.service import run_audit, run_drift_check


def _run_aws_audit(cloud_account_id: str) -> dict:
    db = SessionLocal()
    try:
        account = db.get(CloudAccount, cloud_account_id)
        if account is None:
            return {"error": "account_not_found"}
        scan = run_audit(db, account)
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


if app is not None:  # pragma: no cover - requires celery/broker
    run_aws_audit = app.task(name="cspm.run_aws_audit", queue="high")(_run_aws_audit)
    run_drift_check_task = app.task(name="cspm.run_drift_check", queue="default")(
        _run_drift_check
    )
else:
    run_aws_audit = _run_aws_audit
    run_drift_check_task = _run_drift_check
