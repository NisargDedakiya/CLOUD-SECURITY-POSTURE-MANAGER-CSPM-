"""initial CSPM schema

Creates the cspm_* tables (spec Section 4). Also creates the shared-schema
stub tables (organisations/users/audit_log) when they are absent, so the
isolated docker-compose stack is self-contained. In the real platform the
shared tables already exist and create_all is a no-op for them.

Revision ID: 0001
Revises:
Create Date: 2026-01-01
"""

from __future__ import annotations

from alembic import op

from cspm.db import Base

# Import models so their tables are registered on Base.metadata.
from cspm import models  # noqa: F401
from cspm.shared import models as shared_models  # noqa: F401

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    Base.metadata.create_all(bind=op.get_bind())


def downgrade() -> None:
    Base.metadata.drop_all(bind=op.get_bind())
