"""SQLAlchemy engine, session factory, and declarative base.

The shared platform owns the real Postgres engine; this module provides a
self-contained engine so CSPM can be developed and tested in isolation. In
production the platform injects its own session via :func:`get_db`.
"""

from __future__ import annotations

from collections.abc import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from cspm.config import get_settings


class Base(DeclarativeBase):
    """Declarative base for all CSPM ORM models."""


_settings = get_settings()

# ``check_same_thread`` only matters for SQLite; harmless for Postgres via kwargs.
_engine_kwargs: dict = {"future": True}
if _settings.database_url.startswith("sqlite"):
    from sqlalchemy.pool import StaticPool

    _engine_kwargs.update(
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

engine = create_engine(_settings.database_url, **_engine_kwargs)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, class_=Session)


def init_db() -> None:
    """Create all tables. In production Alembic migrations do this instead."""
    # Import models so they register on the metadata before create_all.
    from cspm import models  # noqa: F401
    from cspm.shared import models as shared_models  # noqa: F401

    Base.metadata.create_all(bind=engine)


def get_db() -> Iterator[Session]:
    """FastAPI dependency yielding a scoped session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
