"""Razorpay billing gateway (INR-friendly, for Indian customers).

Mirrors the Stripe gateway's shape so the billing facade can dispatch to either.
Razorpay's model: a **Subscription** created against a **Plan** returns a hosted
``short_url`` the customer completes. Webhooks (HMAC-SHA256 signed) keep the
local plan in sync.

The client is accessed via :func:`_razorpay` (lazy), which tests monkeypatch to
inject a fake — so the live path is verified without the SDK, keys, or network.

Going live needs your Razorpay account: CSPM_BILLING_MODE=razorpay,
CSPM_RAZORPAY_KEY_ID/SECRET, CSPM_RAZORPAY_WEBHOOK_SECRET, and the plan IDs.
"""

from __future__ import annotations

import hashlib
import hmac
import json

from sqlalchemy.orm import Session

from cspm.billing.entitlements import get_subscription
from cspm.billing.plans import PLANS
from cspm.billing.stripe_gateway import BillingError, change_plan
from cspm.config import get_settings
from cspm.logging_config import get_logger

_log = get_logger("cspm.billing.razorpay")
_settings = get_settings()


def _razorpay():  # pragma: no cover - thin lazy import; tests monkeypatch this
    import razorpay

    return razorpay.Client(
        auth=(_settings.razorpay_key_id, _settings.razorpay_key_secret)
    )


def _plan_id(plan: str) -> str | None:
    return {
        "starter": _settings.razorpay_plan_starter,
        "pro": _settings.razorpay_plan_pro,
    }.get(plan)


def _plan_for_id(plan_id: str | None) -> str:
    reverse = {
        _settings.razorpay_plan_starter: "starter",
        _settings.razorpay_plan_pro: "pro",
    }
    return reverse.get(plan_id, "pro")


def create_checkout(db: Session, org_id: str, plan: str, email: str | None = None) -> dict:
    """Create a Razorpay subscription; return its hosted short_url."""
    if plan not in PLANS or plan in ("free", "enterprise"):
        raise BillingError("Choose a self-serve paid plan (starter or pro).")
    plan_id = _plan_id(plan)
    if not plan_id:
        raise BillingError(f"No Razorpay plan configured for '{plan}'.")
    sub = get_subscription(db, org_id)
    rp = _razorpay()
    subscription = rp.subscription.create(
        {
            "plan_id": plan_id,
            "total_count": 12,  # 12 billing cycles (monthly → ~1 year)
            "customer_notify": 1,
            "notes": {"org_id": org_id, "plan": plan},
        }
    )
    sub.stripe_subscription_id = subscription["id"]  # reuse column for external id
    db.commit()
    return {"mode": "razorpay", "url": subscription.get("short_url"), "plan": plan}


def create_portal(db: Session, org_id: str) -> dict:
    # Razorpay has no hosted customer portal; customers manage via email links.
    raise BillingError("Billing portal is not available for Razorpay; use email management links.")


def list_invoices(db: Session, org_id: str, limit: int = 12) -> list[dict]:
    sub = get_subscription(db, org_id)
    if not sub.stripe_subscription_id:
        return []
    try:
        inv = _razorpay().invoice.all({"subscription_id": sub.stripe_subscription_id})
    except Exception:  # noqa: BLE001
        return []
    return [
        {
            "id": i.get("id"),
            "amount_due": i.get("amount"),
            "currency": i.get("currency"),
            "status": i.get("status"),
            "created": i.get("created_at"),
            "hosted_invoice_url": i.get("short_url"),
        }
        for i in inv.get("items", [])
    ]


def _verify_signature(payload: bytes, signature: str | None) -> bool:
    secret = _settings.razorpay_webhook_secret
    if not secret:
        return True  # dev: no secret configured
    expected = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    return bool(signature) and hmac.compare_digest(expected, signature)


def handle_webhook(db: Session, payload: bytes, signature: str | None) -> dict:
    """Verify HMAC signature and apply the Razorpay event to the local plan."""
    if not _verify_signature(payload, signature):
        raise BillingError("Invalid Razorpay webhook signature.")
    event = json.loads(payload)
    etype = event.get("event", "")
    entity = (
        event.get("payload", {}).get("subscription", {}).get("entity", {})
    )
    notes = entity.get("notes", {}) or {}
    org_id = notes.get("org_id")
    if not org_id:
        return {"handled": etype, "note": "no org_id"}

    if etype in ("subscription.activated", "subscription.charged", "subscription.resumed"):
        change_plan(db, org_id, _plan_for_id(entity.get("plan_id")))
    elif etype in ("subscription.halted", "subscription.pending"):
        sub = get_subscription(db, org_id)
        sub.status = "past_due"
        db.commit()
    elif etype in ("subscription.cancelled", "subscription.completed"):
        change_plan(db, org_id, "free", status="canceled")

    _log.info("processed razorpay event %s", etype)
    return {"handled": etype}
