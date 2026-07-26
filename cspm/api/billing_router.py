"""Subscription & billing endpoints (mounts under /api/v1/cspm/billing)."""

from __future__ import annotations

from datetime import UTC

from fastapi import APIRouter, Body, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from cspm.billing import PLANS, plan_public, usage_summary
from cspm.billing.entitlements import get_subscription
from cspm.billing.stripe_gateway import (
    BillingError,
    create_checkout,
    create_portal,
    handle_webhook,
)
from cspm.db import get_db
from cspm.shared.deps import OrgContext, get_org_context, require_role

billing_router = APIRouter(prefix="/api/v1/cspm/billing", tags=["billing"])
ADMIN = require_role("admin")


@billing_router.get("/plans")
def list_plans(
    ctx: OrgContext = Depends(get_org_context), db: Session = Depends(get_db)
):
    sub = get_subscription(db, ctx.org_id)
    return {
        "current_plan": sub.plan,
        "status": sub.status,
        "plans": [plan_public(p) for p in PLANS.values()],
    }


@billing_router.get("/subscription")
def subscription(
    ctx: OrgContext = Depends(get_org_context), db: Session = Depends(get_db)
):
    from datetime import datetime

    # plan_of() lazily expires a lapsed trial before we read status.
    from cspm.billing.entitlements import plan_of

    plan_of(db, ctx.org_id)
    sub = get_subscription(db, ctx.org_id)
    trial_days_left = None
    if sub.status == "trialing" and sub.trial_ends_at:
        ends = sub.trial_ends_at
        if ends.tzinfo is None:
            ends = ends.replace(tzinfo=UTC)
        delta = ends - datetime.now(UTC)
        trial_days_left = max(0, delta.days + (1 if delta.seconds else 0))
    return {
        "plan": sub.plan,
        "status": sub.status,
        "current_period_end": sub.current_period_end.isoformat() if sub.current_period_end else None,
        "trial_ends_at": sub.trial_ends_at.isoformat() if sub.trial_ends_at else None,
        "trial_days_left": trial_days_left,
        "trial_used": sub.trial_used,
        "usage": usage_summary(db, ctx.org_id),
    }


@billing_router.post("/trial")
def start_trial_endpoint(
    payload: dict = Body(default={}),
    ctx: OrgContext = Depends(ADMIN),
    db: Session = Depends(get_db),
):
    """Start a one-time 14-day Pro trial (no card required)."""
    from cspm.billing.entitlements import start_trial

    sub = start_trial(db, ctx.org_id, payload.get("plan", "pro"))
    return {
        "plan": sub.plan,
        "status": sub.status,
        "trial_ends_at": sub.trial_ends_at.isoformat() if sub.trial_ends_at else None,
    }


@billing_router.post("/checkout")
def checkout(
    payload: dict = Body(...),
    ctx: OrgContext = Depends(ADMIN),
    db: Session = Depends(get_db),
):
    plan = payload.get("plan", "")
    try:
        return create_checkout(db, ctx.org_id, plan)
    except BillingError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@billing_router.post("/portal")
def portal(ctx: OrgContext = Depends(ADMIN), db: Session = Depends(get_db)):
    try:
        return create_portal(db, ctx.org_id)
    except BillingError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@billing_router.post("/webhook")
async def webhook(request: Request, db: Session = Depends(get_db)):
    """Stripe webhook — unauthenticated; verified by signature."""
    payload = await request.body()
    sig = request.headers.get("Stripe-Signature")
    try:
        return handle_webhook(db, payload, sig)
    except Exception as exc:  # noqa: BLE001 - surface as 400 to Stripe for retry
        raise HTTPException(status_code=400, detail=str(exc)) from exc
