"""Service layer: orchestrates audits, persistence, and drift.

Shared by the FastAPI router (synchronous path for dev/tests) and the Celery
tasks (async path in production). Keeping this logic here means both entry
points behave identically.
"""

from __future__ import annotations

from datetime import UTC, datetime

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
    return datetime.now(UTC)


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
    if account.provider == "gcp":
        from cspm.auditors.gcp import GCPAuditor
        from cspm.security.crypto import decrypt

        sa_json = decrypt(account.gcp_sa_key_enc) if account.gcp_sa_key_enc else None
        return GCPAuditor(service_account_json=sa_json, collector=session)
    if account.provider == "azure":
        from cspm.auditors.azure import AzureAuditor
        from cspm.security.crypto import decrypt

        secret = decrypt(account.azure_secret_enc) if account.azure_secret_enc else None
        return AzureAuditor(
            tenant_id=account.azure_tenant_id,
            client_id=account.azure_client_id,
            client_secret=secret,
            collector=session,
        )
    raise NotImplementedError(f"Unsupported provider '{account.provider}'.")


def create_scan_run(db: Session, account: CloudAccount) -> ScanRun:
    """Persist a queued scan run (used before async dispatch)."""
    scan = ScanRun(cloud_account_id=account.id, status="queued")
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


def run_audit(
    db: Session, account: CloudAccount, session=None, scan: ScanRun | None = None
) -> ScanRun:
    """Run all checks for an account, persisting a scan run and its findings.

    If ``scan`` is provided (a previously-queued run) it is populated in place;
    otherwise a new run is created. This lets the API create a queued run and an
    async worker complete the same row.
    """
    if scan is None:
        scan = ScanRun(cloud_account_id=account.id, status="running", started_at=_now())
        db.add(scan)
    else:
        scan.status = "running"
        scan.started_at = _now()
    db.flush()

    try:
        auditor = build_auditor(account, session=session)
        findings: list[Finding] = auditor.run_all()
    except Exception:
        scan.status = "failed"
        scan.completed_at = _now()
        db.commit()
        db.refresh(scan)
        raise

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
    _record_compliance_snapshot(db, account, scan)
    _maybe_alert(account, scan)
    db.refresh(scan)
    return scan


def _record_compliance_snapshot(db: Session, account: CloudAccount, scan: ScanRun) -> None:
    """Snapshot per-framework compliance for this account so it can be trended."""
    from cspm.compliance import compute_scores
    from cspm.models import ComplianceSnapshot

    rows = (
        db.query(FindingRecord.check_id)
        .filter(FindingRecord.cloud_account_id == account.id, FindingRecord.status == "open")
        .distinct()
        .all()
    )
    failed = {r[0] for r in rows}
    for framework, data in compute_scores(failed).items():
        db.add(
            ComplianceSnapshot(
                org_id=account.org_id,
                cloud_account_id=account.id,
                scan_run_id=scan.id,
                framework=framework,
                score=data["score"],
                checks_passed=data["checks_passed"],
                checks_applicable=data["checks_applicable"],
            )
        )
    db.commit()


def _maybe_alert(account: CloudAccount, scan: ScanRun) -> None:
    """Fire outbound alerts for high/critical findings from this scan."""
    from cspm.integrations import dispatch_alert, notifiers_configured

    if not notifiers_configured():
        return
    # Loaded lazily to avoid a hard import cycle; alert on this run's findings.
    from cspm.db import SessionLocal

    db = SessionLocal()
    try:
        findings = (
            db.query(FindingRecord)
            .filter_by(scan_run_id=scan.id)
            .all()
        )
        payload = [
            {"severity": f.severity, "title": f.description or f.check_id, "resource": f.resource}
            for f in findings
        ]
        if payload:
            dispatch_alert(f"CSPM scan {account.label or account.provider}", payload)
    finally:
        db.close()


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
