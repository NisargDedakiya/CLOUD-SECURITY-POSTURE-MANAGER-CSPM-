"""Shared test fixtures: fresh in-memory DB and a seeded org per test."""

import pytest

from cspm.db import Base, SessionLocal, engine, init_db
from cspm.shared.models import Organisation


@pytest.fixture()
def db():
    Base.metadata.drop_all(bind=engine)
    init_db()
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture()
def org(db):
    """An org on the Enterprise plan (so functional tests aren't billing-gated).

    Entitlement/plan behavior is covered separately in test_billing.py with
    explicitly lower-tier orgs.
    """
    from cspm.models import Subscription

    o = Organisation(name="Acme", slug="acme")
    db.add(o)
    db.commit()
    db.refresh(o)
    db.add(Subscription(org_id=o.id, plan="enterprise", status="active"))
    db.commit()
    return o
