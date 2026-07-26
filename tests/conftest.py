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
    o = Organisation(name="Acme", slug="acme")
    db.add(o)
    db.commit()
    db.refresh(o)
    return o
