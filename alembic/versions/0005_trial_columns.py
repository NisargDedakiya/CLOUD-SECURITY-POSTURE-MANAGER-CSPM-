"""add trial columns to cspm_subscriptions

Revision ID: 0005
Revises: 0004
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def _cols(bind):
    return {c["name"] for c in sa.inspect(bind).get_columns("cspm_subscriptions")}


def upgrade() -> None:
    bind = op.get_bind()
    cols = _cols(bind)
    if "trial_ends_at" not in cols:
        op.add_column("cspm_subscriptions", sa.Column("trial_ends_at", sa.DateTime(timezone=True)))
    if "trial_used" not in cols:
        op.add_column(
            "cspm_subscriptions",
            sa.Column("trial_used", sa.Boolean(), server_default=sa.false()),
        )


def downgrade() -> None:
    bind = op.get_bind()
    cols = _cols(bind)
    if "trial_used" in cols:
        op.drop_column("cspm_subscriptions", "trial_used")
    if "trial_ends_at" in cols:
        op.drop_column("cspm_subscriptions", "trial_ends_at")
