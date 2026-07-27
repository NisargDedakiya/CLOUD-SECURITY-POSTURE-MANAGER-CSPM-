"""Stripe billing gateway (production-grade).

Two modes (CSPM_BILLING_MODE):
- ``manual`` : no external gateway. ``change_plan`` sets the plan directly — useful
  for dev, self-hosted, and enterprise contracts closed outside Stripe.
- ``stripe`` : real Checkout + Billing Portal + Customer management + webhook sync.

The Stripe SDK is accessed via :func:`_stripe` (lazy import), which tests can
monkeypatch to inject a fake — so the full live code path is verifiable without
network access or real keys.

Going live still requires *your* Stripe account: set CSPM_BILLING_MODE=stripe,
CSPM_STRIPE_SECRET_KEY, CSPM_STRIPE_WEBHOOK_SECRET, and the price IDs. See
docs/business/pricing-and-company.md.
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


def _stripe():  # pragma: no cover - thin lazy import; tests monkeypatch this
    import stripe

    stripe.api_key = _settings.stripe_secret_key
    return stripe


def _price_id(plan: str) -> str | None:
    return {"starter": _settings.stripe_price_starter, "pro": _settings.stripe_price_pro}.get(plan)


def _plan_for_price(price_id: str | None) -> str:
    reverse = {
        _settings.stripe_price_starter: "starter",
        _settings.stripe_price_pro: "pro",
    }
    return reverse.get(price_id, "pro")


def change_plan(db: Session, org_id: str, plan: str, status: str = "active") -> None:
    """Directly set an org's plan (manual mode / webhook sync)."""
    if plan not in PLANS:
        raise BillingError(f"Unknown plan '{plan}'.")
    sub = get_subscription(db, org_id)
    sub.plan = plan
    sub.status = status
    sub.updated_at = datetime.now(UTC)
    db.commit()


def _ensure_customer(db: Session, org_id: str, email: str | None = None) -> str:
    """Get-or-create a Stripe customer for the org; persist its id."""
    sub = get_subscription(db, org_id)
    if sub.stripe_customer_id:
        return sub.stripe_customer_id
    customer = _stripe().Customer.create(
        email=email, metadata={"org_id": org_id}, idempotency_key=f"cust-{org_id}"
    )
    sub.stripe_customer_id = customer["id"]
    db.commit()
    return customer["id"]


def create_checkout(db: Session, org_id: str, plan: str, email: str | None = None) -> dict:
    """Start an upgrade. Returns a URL the frontend redirects to."""
    if plan not in PLANS or plan in ("free", "enterprise"):
        raise BillingError("Choose a self-serve paid plan (starter or pro).")

    if _settings.billing_mode != "stripe":
        change_plan(db, org_id, plan)
        return {"mode": "manual", "url": _settings.billing_success_url, "plan": plan}

    price = _price_id(plan)
    if not price:
        raise BillingError(f"No Stripe price configured for plan '{plan}'.")
    customer_id = _ensure_customer(db, org_id, email)
    session = _stripe().checkout.Session.create(
        mode="subscription",
        line_items=[{"price": price, "quantity": 1}],
        success_url=_settings.billing_success_url,
        cancel_url=_settings.billing_cancel_url,
        client_reference_id=org_id,
        customer=customer_id,
        metadata={"org_id": org_id, "plan": plan},
        # Idempotency prevents duplicate subscriptions on double-clicks/retries.
        idempotency_key=f"checkout-{org_id}-{plan}",
    )
    return {"mode": "stripe", "url": session["url"], "plan": plan}


def create_portal(db: Session, org_id: str) -> dict:
    if _settings.billing_mode != "stripe":
        raise BillingError("Billing portal requires Stripe mode.")
    sub = get_subscription(db, org_id)
    if not sub.stripe_customer_id:
        raise BillingError("No Stripe customer on file.")
    portal = _stripe().billing_portal.Session.create(
        customer=sub.stripe_customer_id, return_url=_settings.billing_success_url
    )
    return {"url": portal["url"]}


def list_invoices(db: Session, org_id: str, limit: int = 12) -> list[dict]:
    """Return recent invoices for the org's Stripe customer."""
    if _settings.billing_mode != "stripe":
        return []
    sub = get_subscription(db, org_id)
    if not sub.stripe_customer_id:
        return []
    inv = _stripe().Invoice.list(customer=sub.stripe_customer_id, limit=limit)
    return [
        {
            "id": i["id"],
            "amount_due": i.get("amount_due"),
            "currency": i.get("currency"),
            "status": i.get("status"),
            "created": i.get("created"),
            "hosted_invoice_url": i.get("hosted_invoice_url"),
        }
        for i in inv.get("data", [])
    ]


def _period_end(obj: dict):
    ts = obj.get("current_period_end")
    return datetime.fromtimestamp(ts, tz=UTC) if ts else None


def handle_webhook(db: Session, payload: bytes, signature: str | None) -> dict:
    """Verify + apply a Stripe webhook event to keep the local plan in sync."""
    if _settings.stripe_webhook_secret:
        event = _stripe().Webhook.construct_event(
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
        sub.stripe_customer_id = obj.get("customer") or sub.stripe_customer_id
        sub.stripe_subscription_id = obj.get("subscription")
        change_plan(db, org_id, plan)

    elif etype == "customer.subscription.updated" and org_id:
        sub = get_subscription(db, org_id)
        price = ((obj.get("items", {}).get("data") or [{}])[0].get("price") or {}).get("id")
        sub.plan = _plan_for_price(price)
        status = obj.get("status", "active")
        sub.status = "active" if status in ("active", "trialing") else status
        sub.current_period_end = _period_end(obj)
        db.commit()

    elif etype in ("customer.subscription.deleted",) and org_id:
        change_plan(db, org_id, "free", status="canceled")

    elif etype == "invoice.paid" and org_id:
        sub = get_subscription(db, org_id)
        sub.status = "active"
        db.commit()

    elif etype == "invoice.payment_failed" and org_id:
        sub = get_subscription(db, org_id)
        sub.status = "past_due"
        db.commit()

    _log.info("processed stripe event %s", etype)
    return {"handled": etype}
