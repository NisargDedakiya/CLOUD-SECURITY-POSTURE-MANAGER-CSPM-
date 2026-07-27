"""Billing facade — dispatches to the configured payment gateway.

``CSPM_BILLING_MODE``:
- ``manual``   → Stripe module's manual path (plan flips directly)
- ``stripe``   → Stripe Checkout / Portal / webhooks
- ``razorpay`` → Razorpay subscriptions / webhooks (INR-friendly)

The router imports from here so adding a gateway never touches endpoint code.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from cspm.billing import stripe_gateway
from cspm.billing.stripe_gateway import BillingError
from cspm.config import get_settings

# BillingError re-exported for callers.
__all__ = ["BillingError", "create_checkout", "create_portal", "handle_webhook", "list_invoices"]


def _mod():
    if get_settings().billing_mode == "razorpay":
        from cspm.billing import razorpay_gateway

        return razorpay_gateway
    return stripe_gateway  # handles both 'manual' and 'stripe'


def create_checkout(db: Session, org_id: str, plan: str, email: str | None = None) -> dict:
    return _mod().create_checkout(db, org_id, plan, email=email)


def create_portal(db: Session, org_id: str) -> dict:
    return _mod().create_portal(db, org_id)


def list_invoices(db: Session, org_id: str, limit: int = 12) -> list[dict]:
    return _mod().list_invoices(db, org_id, limit=limit)


def handle_webhook(db: Session, payload: bytes, signature: str | None) -> dict:
    return _mod().handle_webhook(db, payload, signature)
