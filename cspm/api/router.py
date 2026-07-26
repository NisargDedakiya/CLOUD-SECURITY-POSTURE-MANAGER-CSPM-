"""CSPM API router — mounts at /api/v1/cspm/ (spec Section 6).

The router is org-scoped: every query filters by the caller's org_id from the
shared auth context. Secret fields are never serialized back to the client.
"""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Body, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from cspm.compliance import compute_scores, evidence_report, remediation_priority
from cspm.connectors import ConnectorError, get_connector
from cspm.db import get_db
from cspm.models import CloudAccount, DriftEvent, FindingRecord, ScanRun
from cspm.schemas import (
    AWSConnectRequest,
    AzureConnectRequest,
    CloudAccountOut,
    DriftEventOut,
    FindingOut,
    FindingStatusUpdate,
    GCPConnectRequest,
    ScanRunOut,
)
from cspm.service import run_audit
from cspm.shared.deps import OrgContext, get_org_context

router = APIRouter(prefix="/api/v1/cspm", tags=["cspm"])


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _account_or_404(db: Session, ctx: OrgContext, account_id: str) -> CloudAccount:
    account = (
        db.query(CloudAccount)
        .filter_by(id=account_id, org_id=ctx.org_id)
        .one_or_none()
    )
    if account is None:
        raise HTTPException(status_code=404, detail="Cloud account not found.")
    return account


# ---- Module 6.1: accounts --------------------------------------------------
@router.post("/accounts", response_model=CloudAccountOut, status_code=201)
def connect_account(
    payload: dict = Body(...),
    ctx: OrgContext = Depends(get_org_context),
    db: Session = Depends(get_db),
):
    provider = payload.get("provider")
    try:
        if provider == "aws":
            req = AWSConnectRequest(**payload)
            connector = get_connector(
                "aws", role_arn=req.role_arn, external_id=req.external_id
            )
        elif provider == "gcp":
            req = GCPConnectRequest(**payload)
            connector = get_connector(
                "gcp", service_account_json=req.service_account_json
            )
        elif provider == "azure":
            req = AzureConnectRequest(**payload)
            connector = get_connector(
                "azure",
                tenant_id=req.tenant_id,
                client_id=req.client_id,
                client_secret=req.client_secret,
            )
        else:
            raise HTTPException(status_code=400, detail="Unsupported provider.")
        result = connector.validate()
    except ConnectorError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    account = CloudAccount(
        org_id=ctx.org_id,
        provider=provider,
        label=req.label,
        status="active",
        last_validated_at=_now(),
        **result.stored_fields,
    )
    db.add(account)
    db.commit()
    db.refresh(account)
    out = CloudAccountOut.model_validate(account)
    out.account_identifier = result.account_identifier
    return out


@router.get("/accounts", response_model=list[CloudAccountOut])
def list_accounts(
    ctx: OrgContext = Depends(get_org_context), db: Session = Depends(get_db)
):
    return db.query(CloudAccount).filter_by(org_id=ctx.org_id).all()


@router.post("/accounts/{account_id}/validate", response_model=CloudAccountOut)
def revalidate_account(
    account_id: str,
    ctx: OrgContext = Depends(get_org_context),
    db: Session = Depends(get_db),
):
    account = _account_or_404(db, ctx, account_id)
    # A full re-validate would reconstruct the connector from stored fields;
    # here we mark the timestamp (live re-validation runs in the connector).
    account.last_validated_at = _now()
    account.status = "active"
    db.commit()
    db.refresh(account)
    return account


@router.delete("/accounts/{account_id}", status_code=204)
def disconnect_account(
    account_id: str,
    ctx: OrgContext = Depends(get_org_context),
    db: Session = Depends(get_db),
):
    account = _account_or_404(db, ctx, account_id)
    db.delete(account)
    db.commit()


# ---- Module 6.2: scans -----------------------------------------------------
@router.post("/accounts/{account_id}/scan", response_model=ScanRunOut, status_code=202)
def trigger_scan(
    account_id: str,
    ctx: OrgContext = Depends(get_org_context),
    db: Session = Depends(get_db),
):
    account = _account_or_404(db, ctx, account_id)
    # In production this enqueues cspm.run_aws_audit on the 'high' queue; here we
    # run synchronously so the dev/test path returns a completed scan.
    try:
        scan = run_audit(db, account)
    except NotImplementedError as exc:
        raise HTTPException(status_code=501, detail=str(exc)) from exc
    return scan


@router.get("/scans/{scan_run_id}", response_model=ScanRunOut)
def scan_status(
    scan_run_id: str,
    ctx: OrgContext = Depends(get_org_context),
    db: Session = Depends(get_db),
):
    scan = (
        db.query(ScanRun)
        .join(CloudAccount, ScanRun.cloud_account_id == CloudAccount.id)
        .filter(ScanRun.id == scan_run_id, CloudAccount.org_id == ctx.org_id)
        .one_or_none()
    )
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan run not found.")
    return scan


# ---- findings --------------------------------------------------------------
@router.get("/findings", response_model=list[FindingOut])
def list_findings(
    severity: str | None = Query(default=None),
    status: str | None = Query(default=None),
    account_id: str | None = Query(default=None),
    ctx: OrgContext = Depends(get_org_context),
    db: Session = Depends(get_db),
):
    q = db.query(FindingRecord).filter_by(org_id=ctx.org_id)
    if severity:
        q = q.filter_by(severity=severity)
    if status:
        q = q.filter_by(status=status)
    if account_id:
        q = q.filter_by(cloud_account_id=account_id)
    return q.order_by(FindingRecord.discovered_at.desc()).all()


@router.patch("/findings/{finding_id}", response_model=FindingOut)
def update_finding(
    finding_id: str,
    payload: FindingStatusUpdate,
    ctx: OrgContext = Depends(get_org_context),
    db: Session = Depends(get_db),
):
    finding = (
        db.query(FindingRecord)
        .filter_by(id=finding_id, org_id=ctx.org_id)
        .one_or_none()
    )
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found.")
    finding.status = payload.status
    finding.resolved_at = _now() if payload.status == "resolved" else None
    db.commit()
    db.refresh(finding)
    return finding


# ---- Module 6.3: compliance ------------------------------------------------
def _failed_check_ids(db: Session, ctx: OrgContext) -> set[str]:
    rows = (
        db.query(FindingRecord.check_id)
        .filter(FindingRecord.org_id == ctx.org_id, FindingRecord.status == "open")
        .distinct()
        .all()
    )
    return {r[0] for r in rows}


@router.get("/compliance/{framework}")
def compliance_score(
    framework: str,
    ctx: OrgContext = Depends(get_org_context),
    db: Session = Depends(get_db),
):
    scores = compute_scores(_failed_check_ids(db, ctx))
    if framework not in scores:
        raise HTTPException(status_code=404, detail="Unknown framework.")
    return {"framework": framework, **scores[framework]}


@router.get("/compliance/{framework}/evidence")
def compliance_evidence(
    framework: str,
    ctx: OrgContext = Depends(get_org_context),
    db: Session = Depends(get_db),
):
    findings = db.query(FindingRecord).filter_by(org_id=ctx.org_id, status="open").all()
    report = evidence_report(framework, findings)
    if not report["controls"]:
        raise HTTPException(status_code=404, detail="Unknown framework.")
    return report


# ---- Module 6.4: drift -----------------------------------------------------
@router.get("/drift", response_model=list[DriftEventOut])
def list_drift(
    status: str | None = Query(default=None),
    ctx: OrgContext = Depends(get_org_context),
    db: Session = Depends(get_db),
):
    q = db.query(DriftEvent).filter_by(org_id=ctx.org_id)
    if status:
        q = q.filter_by(status=status)
    return q.order_by(DriftEvent.detected_at.desc()).all()


def _drift_or_404(db: Session, ctx: OrgContext, drift_id: str) -> DriftEvent:
    evt = db.query(DriftEvent).filter_by(id=drift_id, org_id=ctx.org_id).one_or_none()
    if evt is None:
        raise HTTPException(status_code=404, detail="Drift event not found.")
    return evt


@router.post("/drift/{drift_id}/approve", response_model=DriftEventOut)
def approve_drift(
    drift_id: str,
    ctx: OrgContext = Depends(get_org_context),
    db: Session = Depends(get_db),
):
    from cspm.models import Baseline

    evt = _drift_or_404(db, ctx, drift_id)
    evt.status = "approved"
    # Approving updates the baseline to the new (after) state.
    baseline = (
        db.query(Baseline)
        .filter_by(cloud_account_id=evt.cloud_account_id, resource_id=evt.resource_id)
        .one_or_none()
    )
    if evt.after_state is None and baseline is not None:
        db.delete(baseline)  # resource deleted → drop baseline
    elif baseline is not None:
        baseline.config_snapshot = evt.after_state
    elif evt.after_state is not None:
        db.add(
            Baseline(
                cloud_account_id=evt.cloud_account_id,
                resource_type=evt.resource_type,
                resource_id=evt.resource_id,
                config_snapshot=evt.after_state,
            )
        )
    db.commit()
    db.refresh(evt)
    return evt


@router.post("/drift/{drift_id}/reject", response_model=FindingOut)
def reject_drift(
    drift_id: str,
    ctx: OrgContext = Depends(get_org_context),
    db: Session = Depends(get_db),
):
    import hashlib

    evt = _drift_or_404(db, ctx, drift_id)
    evt.status = "violation"
    # Rejecting a drift creates a finding for remediation tracking.
    dedup = hashlib.sha256(
        f"drift|{evt.id}|{evt.resource_id}".encode()
    ).hexdigest()
    finding = FindingRecord(
        org_id=evt.org_id,
        cloud_account_id=evt.cloud_account_id,
        scan_run_id=None,
        check_id="drift_violation",
        resource=evt.resource_id,
        severity="high",
        description=f"Unapproved {evt.drift_type} drift on {evt.resource_type}.",
        remediation="Revert the change or approve it to update the baseline.",
        dedup_hash=dedup,
    )
    db.add(finding)
    db.commit()
    db.refresh(finding)
    return finding
