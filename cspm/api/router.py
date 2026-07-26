"""CSPM API router — mounts at /api/v1/cspm/ (spec Section 6).

Org-scoped: every query filters by the caller's org_id. Mutations are RBAC-gated
and recorded to the shared audit_log. Secret fields are never serialized back.
List endpoints are bounded (limit/offset + X-Total-Count).
"""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Body, Depends, HTTPException, Response
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session

from cspm.api.pagination import limit_param, offset_param, paginate
from cspm.billing.entitlements import (
    check_account_limit,
    check_scan_quota,
    plan_of,
    require_feature,
)
from cspm.billing.plans import Feature
from cspm.compliance import compute_scores, evidence_report
from cspm.config import get_settings
from cspm.connectors import ConnectorError, get_connector
from cspm.db import get_db
from cspm.logging_config import get_logger
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
from cspm.service import create_scan_run, run_audit
from cspm.shared.audit import record_action
from cspm.shared.deps import OrgContext, get_org_context, require_role

router = APIRouter(prefix="/api/v1/cspm", tags=["cspm"])
_log = get_logger("cspm.router")
_settings = get_settings()

# RBAC role sets.
WRITE = require_role("admin", "analyst")
ADMIN = require_role("admin")


def _now() -> datetime:
    return datetime.now(UTC)


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
    ctx: OrgContext = Depends(WRITE),
    db: Session = Depends(get_db),
):
    provider = payload.get("provider")
    # Entitlements: account cap for all, multi-cloud gated to paid plans.
    check_account_limit(db, ctx.org_id)
    if provider in ("gcp", "azure"):
        require_feature(db, ctx.org_id, Feature.MULTI_CLOUD)
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
                subscription_id=req.subscription_id,
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
    record_action(
        db,
        org_id=ctx.org_id,
        user_id=ctx.user_id,
        action="cspm.account.connect",
        resource=account.id,
        meta={"provider": provider},
        ip_addr=ctx.ip_addr,
    )
    out = CloudAccountOut.model_validate(account)
    out.account_identifier = result.account_identifier
    return out


@router.get("/accounts", response_model=list[CloudAccountOut])
def list_accounts(
    response: Response,
    limit: int = limit_param(),
    offset: int = offset_param(),
    ctx: OrgContext = Depends(get_org_context),
    db: Session = Depends(get_db),
):
    q = db.query(CloudAccount).filter_by(org_id=ctx.org_id).order_by(
        CloudAccount.created_at.desc()
    )
    return paginate(q, response, limit, offset)


@router.post("/accounts/{account_id}/validate", response_model=CloudAccountOut)
def revalidate_account(
    account_id: str,
    ctx: OrgContext = Depends(WRITE),
    db: Session = Depends(get_db),
):
    account = _account_or_404(db, ctx, account_id)
    account.last_validated_at = _now()
    account.status = "active"
    db.commit()
    db.refresh(account)
    return account


@router.delete("/accounts/{account_id}", status_code=204)
def disconnect_account(
    account_id: str,
    ctx: OrgContext = Depends(ADMIN),
    db: Session = Depends(get_db),
):
    account = _account_or_404(db, ctx, account_id)
    db.delete(account)
    db.commit()
    record_action(
        db,
        org_id=ctx.org_id,
        user_id=ctx.user_id,
        action="cspm.account.disconnect",
        resource=account_id,
        ip_addr=ctx.ip_addr,
    )


# ---- Module 6.2: scans -----------------------------------------------------
@router.post("/accounts/{account_id}/scan", response_model=ScanRunOut, status_code=202)
def trigger_scan(
    account_id: str,
    ctx: OrgContext = Depends(WRITE),
    db: Session = Depends(get_db),
):
    account = _account_or_404(db, ctx, account_id)
    check_scan_quota(db, ctx.org_id)
    record_action(
        db,
        org_id=ctx.org_id,
        user_id=ctx.user_id,
        action="cspm.scan.trigger",
        resource=account_id,
        ip_addr=ctx.ip_addr,
    )
    if _settings.eager_tasks:
        try:
            return run_audit(db, account)
        except NotImplementedError as exc:
            raise HTTPException(status_code=501, detail=str(exc)) from exc
    # Async path: persist a queued run and enqueue the audit on the 'high' queue.
    scan = create_scan_run(db, account)
    from cspm.tasks import run_aws_audit

    run_aws_audit.delay(account.id, scan.id)  # type: ignore[attr-defined]
    return scan


@router.post("/dev/seed", status_code=201)
def dev_seed(
    ctx: OrgContext = Depends(WRITE),
    db: Session = Depends(get_db),
):
    """Dev/demo helper: create a mock AWS account and run a scan with sample data.

    Disabled in production. Lets the dashboard be explored without cloud creds.
    """
    if _settings.is_production:
        raise HTTPException(status_code=404, detail="Not available.")
    from cspm.fakes import FakeAWSSession

    account = CloudAccount(
        org_id=ctx.org_id,
        provider="aws",
        label="demo-aws",
        role_arn="arn:aws:iam::123456789012:role/demo",
        external_id="demo",
        status="active",
        last_validated_at=_now(),
    )
    db.add(account)
    db.commit()
    db.refresh(account)
    scan = run_audit(db, account, session=FakeAWSSession())
    return {"account_id": account.id, "scan_run_id": scan.id, "findings": scan.findings_count}


@router.post("/accounts/{account_id}/prowler-ingest", response_model=ScanRunOut, status_code=202)
def ingest_prowler(
    account_id: str,
    payload: dict = Body(...),
    ctx: OrgContext = Depends(WRITE),
    db: Session = Depends(get_db),
):
    """Ingest Prowler results (OCSF/JSON) as a scan run — hundreds of checks.

    Run `prowler aws -M json-ocsf` in your pipeline and POST the JSON here as
    ``{"results": [...]}``. Gated by the Prowler feature (Pro+).
    """
    require_feature(db, ctx.org_id, Feature.PROWLER)
    account = _account_or_404(db, ctx, account_id)
    check_scan_quota(db, ctx.org_id)

    from cspm.auditors.prowler import parse_prowler_json
    from cspm.service import ingest_findings

    results = payload.get("results")
    if not isinstance(results, list):
        raise HTTPException(status_code=400, detail="Expected {'results': [...]}.")
    findings = parse_prowler_json(results)
    scan = ingest_findings(db, account, findings, engine="prowler")
    record_action(
        db, org_id=ctx.org_id, user_id=ctx.user_id, action="cspm.prowler.ingest",
        resource=account_id, meta={"ingested": scan.findings_count}, ip_addr=ctx.ip_addr,
    )
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
    response: Response,
    severity: str | None = None,
    status: str | None = None,
    account_id: str | None = None,
    limit: int = limit_param(),
    offset: int = offset_param(),
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
    q = q.order_by(FindingRecord.discovered_at.desc())
    return paginate(q, response, limit, offset)


@router.get("/findings/{finding_id}/remediation")
def finding_remediation(
    finding_id: str,
    ctx: OrgContext = Depends(get_org_context),
    db: Session = Depends(get_db),
):
    from cspm.remediation import remediation_for

    finding = (
        db.query(FindingRecord).filter_by(id=finding_id, org_id=ctx.org_id).one_or_none()
    )
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found.")
    return {
        "check_id": finding.check_id,
        "resource": finding.resource,
        "guidance": finding.remediation,
        "snippets": remediation_for(finding.check_id),
    }


@router.get("/reports/findings.csv")
def export_findings_csv(
    ctx: OrgContext = Depends(get_org_context),
    db: Session = Depends(get_db),
):
    from cspm.reporting import findings_csv

    return PlainTextResponse(
        findings_csv(db, ctx.org_id),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=cspm-findings.csv"},
    )


@router.get("/compliance/{framework}/trend")
def compliance_trend_endpoint(
    framework: str,
    ctx: OrgContext = Depends(get_org_context),
    db: Session = Depends(get_db),
):
    from cspm.reporting import compliance_trend

    return {"framework": framework, "series": compliance_trend(db, ctx.org_id, framework)}


@router.get("/audit/verify")
def verify_audit_chain(
    ctx: OrgContext = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    from cspm.shared.audit import verify_chain

    return {"org_id": ctx.org_id, "intact": verify_chain(db, ctx.org_id)}


@router.patch("/findings/{finding_id}", response_model=FindingOut)
def update_finding(
    finding_id: str,
    payload: FindingStatusUpdate,
    ctx: OrgContext = Depends(WRITE),
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
    record_action(
        db,
        org_id=ctx.org_id,
        user_id=ctx.user_id,
        action="cspm.finding.update",
        resource=finding_id,
        meta={"status": payload.status},
        ip_addr=ctx.ip_addr,
    )
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
    if not plan_of(db, ctx.org_id).allows_framework(framework):
        from cspm.billing.entitlements import EntitlementError

        raise EntitlementError(f"Framework '{framework}' requires an upgrade.", "starter")
    return {"framework": framework, **scores[framework]}


@router.get("/compliance/{framework}/evidence")
def compliance_evidence(
    framework: str,
    ctx: OrgContext = Depends(get_org_context),
    db: Session = Depends(get_db),
):
    require_feature(db, ctx.org_id, Feature.EVIDENCE_EXPORT)
    findings = db.query(FindingRecord).filter_by(org_id=ctx.org_id, status="open").all()
    report = evidence_report(framework, findings)
    if not report["controls"]:
        raise HTTPException(status_code=404, detail="Unknown framework.")
    return report


# ---- Module 6.4: drift -----------------------------------------------------
@router.get("/drift", response_model=list[DriftEventOut])
def list_drift(
    response: Response,
    status: str | None = None,
    limit: int = limit_param(),
    offset: int = offset_param(),
    ctx: OrgContext = Depends(get_org_context),
    db: Session = Depends(get_db),
):
    require_feature(db, ctx.org_id, Feature.DRIFT)
    q = db.query(DriftEvent).filter_by(org_id=ctx.org_id)
    if status:
        q = q.filter_by(status=status)
    q = q.order_by(DriftEvent.detected_at.desc())
    return paginate(q, response, limit, offset)


def _drift_or_404(db: Session, ctx: OrgContext, drift_id: str) -> DriftEvent:
    evt = db.query(DriftEvent).filter_by(id=drift_id, org_id=ctx.org_id).one_or_none()
    if evt is None:
        raise HTTPException(status_code=404, detail="Drift event not found.")
    return evt


@router.post("/drift/{drift_id}/approve", response_model=DriftEventOut)
def approve_drift(
    drift_id: str,
    ctx: OrgContext = Depends(WRITE),
    db: Session = Depends(get_db),
):
    from cspm.models import Baseline

    evt = _drift_or_404(db, ctx, drift_id)
    evt.status = "approved"
    baseline = (
        db.query(Baseline)
        .filter_by(cloud_account_id=evt.cloud_account_id, resource_id=evt.resource_id)
        .one_or_none()
    )
    if evt.after_state is None and baseline is not None:
        db.delete(baseline)
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
    record_action(
        db,
        org_id=ctx.org_id,
        user_id=ctx.user_id,
        action="cspm.drift.approve",
        resource=drift_id,
        ip_addr=ctx.ip_addr,
    )
    return evt


@router.post("/drift/{drift_id}/reject", response_model=FindingOut)
def reject_drift(
    drift_id: str,
    ctx: OrgContext = Depends(WRITE),
    db: Session = Depends(get_db),
):
    import hashlib

    evt = _drift_or_404(db, ctx, drift_id)
    evt.status = "violation"
    dedup = hashlib.sha256(f"drift|{evt.id}|{evt.resource_id}".encode()).hexdigest()
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
    record_action(
        db,
        org_id=ctx.org_id,
        user_id=ctx.user_id,
        action="cspm.drift.reject",
        resource=drift_id,
        ip_addr=ctx.ip_addr,
    )
    return finding
