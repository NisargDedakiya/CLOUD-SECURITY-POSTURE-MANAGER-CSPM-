"""Entitlements engine: resolve an org's plan and enforce features/quotas."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy.orm import Session

from cspm.billing.plans import UNLIMITED, Feature, Plan, get_plan
from cspm.models import CloudAccount, ScanRun, Subscription


class EntitlementError(Exception):
    """Raised when an action exceeds the org's plan. Carries the required plan."""

    def __init__(self, message: str, upgrade_to: str = "pro") -> None:
        super().__init__(message)
        self.upgrade_to = upgrade_to


def get_subscription(db: Session, org_id: str) -> Subscription:
    """Return the org's subscription, creating a default (free) one if absent."""
    sub = db.query(Subscription).filter_by(org_id=org_id).one_or_none()
    if sub is None:
        sub = Subscription(org_id=org_id, plan="free", status="active")
        db.add(sub)
        db.commit()
        db.refresh(sub)
    return sub


def plan_of(db: Session, org_id: str) -> Plan:
    sub = get_subscription(db, org_id)
    # A past_due/canceled subscription falls back to the free tier's limits.
    if sub.status not in ("active", "trialing"):
        return get_plan("free")
    return get_plan(sub.plan)


def has_feature(db: Session, org_id: str, feature: Feature) -> bool:
    return plan_of(db, org_id).has(feature)


def require_feature(db: Session, org_id: str, feature: Feature) -> None:
    if not has_feature(db, org_id, feature):
        raise EntitlementError(
            f"'{feature.value}' is not included in your plan.", upgrade_to="pro"
        )


def frameworks_for(db: Session, org_id: str) -> Plan:
    return plan_of(db, org_id)


def check_account_limit(db: Session, org_id: str) -> None:
    plan = plan_of(db, org_id)
    if plan.max_accounts == UNLIMITED:
        return
    count = db.query(CloudAccount).filter_by(org_id=org_id).count()
    if count >= plan.max_accounts:
        raise EntitlementError(
            f"Plan '{plan.name}' allows {plan.max_accounts} cloud account(s).",
            upgrade_to="pro" if plan.id != "pro" else "enterprise",
        )


def _scans_this_month(db: Session, org_id: str) -> int:
    now = datetime.now(UTC)
    start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    return (
        db.query(ScanRun)
        .join(CloudAccount, ScanRun.cloud_account_id == CloudAccount.id)
        .filter(CloudAccount.org_id == org_id, ScanRun.started_at >= start)
        .count()
    )


def check_scan_quota(db: Session, org_id: str) -> None:
    plan = plan_of(db, org_id)
    if plan.max_scans_per_month == UNLIMITED:
        return
    if _scans_this_month(db, org_id) >= plan.max_scans_per_month:
        raise EntitlementError(
            f"Monthly scan limit reached ({plan.max_scans_per_month}) on '{plan.name}'.",
            upgrade_to="pro" if plan.id != "pro" else "enterprise",
        )


def check_api_key_limit(db: Session, org_id: str) -> None:
    from cspm.shared.models import ApiKey

    plan = plan_of(db, org_id)
    if not plan.has(Feature.API_KEYS):
        raise EntitlementError("API keys require a paid plan.", upgrade_to="starter")
    if plan.max_api_keys == UNLIMITED:
        return
    count = db.query(ApiKey).filter_by(org_id=org_id, revoked=False).count()
    if count >= plan.max_api_keys:
        raise EntitlementError(
            f"Plan '{plan.name}' allows {plan.max_api_keys} API key(s).", upgrade_to="pro"
        )


def usage_summary(db: Session, org_id: str) -> dict:
    from cspm.shared.models import ApiKey

    plan = plan_of(db, org_id)

    def cap(v: int) -> str | int:
        return "unlimited" if v == UNLIMITED else v

    return {
        "plan": plan.id,
        "plan_name": plan.name,
        "accounts": {
            "used": db.query(CloudAccount).filter_by(org_id=org_id).count(),
            "limit": cap(plan.max_accounts),
        },
        "scans_this_month": {
            "used": _scans_this_month(db, org_id),
            "limit": cap(plan.max_scans_per_month),
        },
        "api_keys": {
            "used": db.query(ApiKey).filter_by(org_id=org_id, revoked=False).count(),
            "limit": cap(plan.max_api_keys),
        },
        "features": [f.value for f in Feature if plan.has(f)],
        "frameworks": list(plan.frameworks),
    }
