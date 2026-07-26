"""add cspm_subscriptions table

Revision ID: 0004
Revises: 0003
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def _has_table(bind, table: str) -> bool:
    return table in sa.inspect(bind).get_table_names()


def upgrade() -> None:
    bind = op.get_bind()
    if _has_table(bind, "cspm_subscriptions"):
        return  # 0001 create_all already built it on a fresh DB
    op.create_table(
        "cspm_subscriptions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organisations.id", ondelete="CASCADE"), unique=True),
        sa.Column("plan", sa.String(50), server_default="free"),
        sa.Column("status", sa.String(30), server_default="active"),
        sa.Column("stripe_customer_id", sa.String(255)),
        sa.Column("stripe_subscription_id", sa.String(255)),
        sa.Column("current_period_end", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True)),
        sa.Column("updated_at", sa.DateTime(timezone=True)),
    )


def downgrade() -> None:
    bind = op.get_bind()
    if _has_table(bind, "cspm_subscriptions"):
        op.drop_table("cspm_subscriptions")
