"""Verify the Razorpay code path with an injected fake client (no keys/network)."""

import hashlib
import hmac
import importlib
import json

import pytest

from cspm.models import Subscription
from cspm.shared.models import Organisation


@pytest.fixture()
def free_org(db):
    o = Organisation(name="INR Co", slug="inr-co")
    db.add(o)
    db.commit()
    db.refresh(o)
    return o


class _FakeRazorpay:
    def __init__(self):
        self.created = []
        gw = self

        class subscription:
            @staticmethod
            def create(payload):
                gw.created.append(payload)
                return {"id": "sub_rzp_1", "short_url": "https://rzp.io/i/abc"}

        class invoice:
            @staticmethod
            def all(q):
                return {"items": [{"id": "inv_1", "amount": 4900, "currency": "INR",
                                   "status": "paid", "created_at": 1700000000,
                                   "short_url": "https://rzp.io/inv/1"}]}

        self.subscription = subscription
        self.invoice = invoice


@pytest.fixture()
def rzp_gw(monkeypatch):
    monkeypatch.setenv("CSPM_BILLING_MODE", "razorpay")
    monkeypatch.setenv("CSPM_RAZORPAY_KEY_ID", "rzp_test")
    monkeypatch.setenv("CSPM_RAZORPAY_KEY_SECRET", "secret")
    monkeypatch.setenv("CSPM_RAZORPAY_WEBHOOK_SECRET", "whsec")
    monkeypatch.setenv("CSPM_RAZORPAY_PLAN_STARTER", "plan_starter")
    monkeypatch.setenv("CSPM_RAZORPAY_PLAN_PRO", "plan_pro")
    import cspm.config as cfg
    importlib.reload(cfg)
    import cspm.billing.razorpay_gateway as gw
    importlib.reload(gw)
    fake = _FakeRazorpay()
    monkeypatch.setattr(gw, "_razorpay", lambda: fake)
    yield gw, fake
    monkeypatch.undo()
    importlib.reload(cfg)
    importlib.reload(gw)


def _sign(body: bytes) -> str:
    return hmac.new(b"whsec", body, hashlib.sha256).hexdigest()


def test_checkout_creates_subscription(db, free_org, rzp_gw):
    gw, fake = rzp_gw
    r = gw.create_checkout(db, free_org.id, "pro")
    assert r["mode"] == "razorpay" and r["url"].startswith("https://rzp.io/")
    assert fake.created[0]["plan_id"] == "plan_pro"
    assert db.query(Subscription).filter_by(org_id=free_org.id).one().stripe_subscription_id == "sub_rzp_1"


def test_invoices(db, free_org, rzp_gw):
    gw, _ = rzp_gw
    gw.create_checkout(db, free_org.id, "pro")
    inv = gw.list_invoices(db, free_org.id)
    assert inv and inv[0]["currency"] == "INR"


def test_webhook_signature_required(db, free_org, rzp_gw):
    gw, _ = rzp_gw
    body = json.dumps({"event": "subscription.activated", "payload": {}}).encode()
    with pytest.raises(gw.BillingError):
        gw.handle_webhook(db, body, "wrong-sig")


def test_webhook_activates_and_cancels(db, free_org, rzp_gw):
    gw, _ = rzp_gw
    activate = json.dumps({
        "event": "subscription.activated",
        "payload": {"subscription": {"entity": {"plan_id": "plan_pro",
                    "notes": {"org_id": free_org.id, "plan": "pro"}}}},
    }).encode()
    gw.handle_webhook(db, activate, _sign(activate))
    assert db.query(Subscription).filter_by(org_id=free_org.id).one().plan == "pro"

    cancel = json.dumps({
        "event": "subscription.cancelled",
        "payload": {"subscription": {"entity": {"notes": {"org_id": free_org.id}}}},
    }).encode()
    gw.handle_webhook(db, cancel, _sign(cancel))
    sub = db.query(Subscription).filter_by(org_id=free_org.id).one()
    assert sub.plan == "free" and sub.status == "canceled"


def test_facade_dispatches_to_razorpay(db, free_org, rzp_gw, monkeypatch):
    import cspm.billing.gateway as facade
    importlib.reload(facade)
    r = facade.create_checkout(db, free_org.id, "pro")
    assert r["mode"] == "razorpay"
