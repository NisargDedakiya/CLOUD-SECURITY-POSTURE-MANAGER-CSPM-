"""Stripe billing gateway.

Two modes (CSPM_BILLING_MODE):
- ``manual`` : no external gateway. ``change_plan`` sets the plan directly — useful
  for dev, self-hosted, and enterprise contracts closed outside Stripe.
- ``stripe`` : Checkout for upgrades, Billing Portal for management, and webhook
  handling to keep the local subscription in sync.

The Stripe SDK is imported lazily so it's only needed when ``stripe`` mode is on.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy.orm import Session

from cspm.billing.entitlements import get_subscription
from cspm.billing.plans import PLANS
from cspm.config import get_settings
from cspm.logging_config import get_logger

_log = get_logger("cspm.billing")
_settings = get_settings()


class BillingError(Exception):
    pass


def _price_id(plan: str) -> str | None:
    return {"starter": _settings.stripe_price_starter, "pro": _settings.stripe_price_pro}.get(plan)


def change_plan(db: Session, org_id: str, plan: str, status: str = "active") -> None:
    """Directly set an org's plan (manual mode / webhook sync)."""
    if plan not in PLANS:
        raise BillingError(f"Unknown plan '{plan}'.")
    sub = get_subscription(db, org_id)
    sub.plan = plan
    sub.status = status
    sub.updated_at = datetime.now(UTC)
    db.commit()


def create_checkout(db: Session, org_id: str, plan: str) -> dict:
    """Start an upgrade. Returns a URL the frontend redirects to.

    In manual mode the change is applied immediately and a local URL returned.
    """
    if plan not in PLANS or plan in ("free", "enterprise"):
        raise BillingError("Choose a self-serve paid plan (starter or pro).")

    if _settings.billing_mode != "stripe":
        change_plan(db, org_id, plan)
        return {"mode": "manual", "url": _settings.billing_success_url, "plan": plan}

    import stripe  # pragma: no cover - requires stripe

    stripe.api_key = _settings.stripe_secret_key
    price = _price_id(plan)
    if not price:
        raise BillingError(f"No Stripe price configured for plan '{plan}'.")
    sub = get_subscription(db, org_id)
    session = stripe.checkout.Session.create(
        mode="subscription",
        line_items=[{"price": price, "quantity": 1}],
        success_url=_settings.billing_success_url,
        cancel_url=_settings.billing_cancel_url,
        client_reference_id=org_id,
        customer=sub.stripe_customer_id or None,
        metadata={"org_id": org_id, "plan": plan},
    )
    return {"mode": "stripe", "url": session.url, "plan": plan}


def create_portal(db: Session, org_id: str) -> dict:  # pragma: no cover - requires stripe
    if _settings.billing_mode != "stripe":
        raise BillingError("Billing portal requires Stripe mode.")
    import stripe

    stripe.api_key = _settings.stripe_secret_key
    sub = get_subscription(db, org_id)
    if not sub.stripe_customer_id:
        raise BillingError("No Stripe customer on file.")
    portal = stripe.billing_portal.Session.create(
        customer=sub.stripe_customer_id, return_url=_settings.billing_success_url
    )
    return {"url": portal.url}


def handle_webhook(db: Session, payload: bytes, signature: str | None) -> dict:  # pragma: no cover - requires stripe
    """Verify + apply a Stripe webhook event to keep the local plan in sync."""
    import stripe

    if _settings.stripe_webhook_secret:
        event = stripe.Webhook.construct_event(
            payload, signature, _settings.stripe_webhook_secret
        )
    else:
        import json

        event = json.loads(payload)

    etype = event["type"]
    obj = event["data"]["object"]
    org_id = (obj.get("metadata") or {}).get("org_id") or obj.get("client_reference_id")

    if etype == "checkout.session.completed" and org_id:
        plan = (obj.get("metadata") or {}).get("plan", "pro")
        sub = get_subscription(db, org_id)
        sub.stripe_customer_id = obj.get("customer")
        sub.stripe_subscription_id = obj.get("subscription")
        change_plan(db, org_id, plan)
    elif etype in ("customer.subscription.deleted",) and org_id:
        change_plan(db, org_id, "free", status="canceled")
    elif etype == "invoice.payment_failed" and org_id:
        sub = get_subscription(db, org_id)
        sub.status = "past_due"
        db.commit()

    _log.info("processed stripe event %s", etype)
    return {"handled": etype}
