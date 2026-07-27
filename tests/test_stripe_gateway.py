"""Verify the *real* Stripe code path with an injected fake SDK (no network,
no keys). Exercises checkout, customer creation, portal, invoices, and every
webhook branch."""

import importlib
import json

import pytest

from cspm.models import Subscription
from cspm.shared.models import Organisation


@pytest.fixture()
def free_org(db):
    o = Organisation(name="Pay Co", slug="pay-co")
    db.add(o)
    db.commit()
    db.refresh(o)
    return o


class _FakeStripe:
    """Minimal stand-in for the stripe module used by the gateway."""

    def __init__(self):
        self.created_sessions = []
        self.created_customers = []

        gw = self

        class checkout:
            class Session:
                @staticmethod
                def create(**kw):
                    gw.created_sessions.append(kw)
                    return {"id": "cs_1", "url": "https://checkout.stripe.test/cs_1"}

        class billing_portal:
            class Session:
                @staticmethod
                def create(**kw):
                    return {"id": "ps_1", "url": "https://portal.stripe.test/ps_1"}

        class Customer:
            @staticmethod
            def create(**kw):
                gw.created_customers.append(kw)
                return {"id": "cus_123"}

        class Invoice:
            @staticmethod
            def list(**kw):
                return {"data": [{"id": "in_1", "amount_due": 29900, "currency": "usd",
                                  "status": "paid", "created": 1700000000,
                                  "hosted_invoice_url": "https://inv.test/in_1"}]}

        class Webhook:
            @staticmethod
            def construct_event(payload, sig, secret):
                return json.loads(payload)

        self.checkout = checkout
        self.billing_portal = billing_portal
        self.Customer = Customer
        self.Invoice = Invoice
        self.Webhook = Webhook


@pytest.fixture()
def stripe_gw(monkeypatch):
    """Reload the gateway in 'stripe' mode with configured prices + a fake SDK."""
    monkeypatch.setenv("CSPM_BILLING_MODE", "stripe")
    monkeypatch.setenv("CSPM_STRIPE_SECRET_KEY", "sk_test_x")
    monkeypatch.setenv("CSPM_STRIPE_PRICE_STARTER", "price_starter")
    monkeypatch.setenv("CSPM_STRIPE_PRICE_PRO", "price_pro")
    import cspm.config as cfg
    importlib.reload(cfg)
    import cspm.billing.stripe_gateway as gw
    importlib.reload(gw)
    fake = _FakeStripe()
    monkeypatch.setattr(gw, "_stripe", lambda: fake)
    yield gw, fake
    # restore modules to default (manual) config for other tests
    monkeypatch.undo()
    importlib.reload(cfg)
    importlib.reload(gw)


def test_checkout_creates_customer_and_session(db, free_org, stripe_gw):
    gw, fake = stripe_gw
    result = gw.create_checkout(db, free_org.id, "pro", email="cto@payco.test")
    assert result["mode"] == "stripe"
    assert result["url"].startswith("https://checkout.stripe.test/")
    # A customer was created and persisted.
    assert fake.created_customers and fake.created_customers[0]["metadata"]["org_id"] == free_org.id
    assert db.query(Subscription).filter_by(org_id=free_org.id).one().stripe_customer_id == "cus_123"
    # Checkout used the configured price + idempotency key.
    sess = fake.created_sessions[0]
    assert sess["line_items"][0]["price"] == "price_pro"
    assert sess["idempotency_key"].startswith("checkout-")


def test_portal_requires_customer(db, free_org, stripe_gw):
    gw, _ = stripe_gw
    with pytest.raises(gw.BillingError):
        gw.create_portal(db, free_org.id)  # no customer yet
    gw.create_checkout(db, free_org.id, "pro")  # creates customer
    assert gw.create_portal(db, free_org.id)["url"].startswith("https://portal.stripe.test/")


def test_invoices_listing(db, free_org, stripe_gw):
    gw, _ = stripe_gw
    gw.create_checkout(db, free_org.id, "pro")
    inv = gw.list_invoices(db, free_org.id)
    assert inv and inv[0]["status"] == "paid"


def test_webhook_checkout_completed_activates_plan(db, free_org, stripe_gw):
    gw, _ = stripe_gw
    payload = json.dumps({
        "type": "checkout.session.completed",
        "data": {"object": {"client_reference_id": free_org.id, "customer": "cus_123",
                             "subscription": "sub_1", "metadata": {"org_id": free_org.id, "plan": "pro"}}},
    }).encode()
    gw.handle_webhook(db, payload, "sig")
    sub = db.query(Subscription).filter_by(org_id=free_org.id).one()
    assert sub.plan == "pro" and sub.status == "active" and sub.stripe_subscription_id == "sub_1"


def test_webhook_subscription_updated_maps_price(db, free_org, stripe_gw):
    gw, _ = stripe_gw
    payload = json.dumps({
        "type": "customer.subscription.updated",
        "data": {"object": {"metadata": {"org_id": free_org.id}, "status": "active",
                            "current_period_end": 1800000000,
                            "items": {"data": [{"price": {"id": "price_starter"}}]}}},
    }).encode()
    gw.handle_webhook(db, payload, "sig")
    sub = db.query(Subscription).filter_by(org_id=free_org.id).one()
    assert sub.plan == "starter" and sub.current_period_end is not None


def test_webhook_payment_failed_and_deleted(db, free_org, stripe_gw):
    gw, _ = stripe_gw
    fail = json.dumps({"type": "invoice.payment_failed",
                       "data": {"object": {"metadata": {"org_id": free_org.id}}}}).encode()
    gw.handle_webhook(db, fail, "sig")
    assert db.query(Subscription).filter_by(org_id=free_org.id).one().status == "past_due"

    deleted = json.dumps({"type": "customer.subscription.deleted",
                          "data": {"object": {"metadata": {"org_id": free_org.id}}}}).encode()
    gw.handle_webhook(db, deleted, "sig")
    sub = db.query(Subscription).filter_by(org_id=free_org.id).one()
    assert sub.plan == "free" and sub.status == "canceled"
