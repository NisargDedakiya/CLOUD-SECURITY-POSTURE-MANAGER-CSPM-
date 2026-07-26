"""add azure_subscription_id to cspm_cloud_accounts

Required for live Azure resource enumeration (Reader on the subscription).

Revision ID: 0003
Revises: 0002
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def _has_column(bind, table: str, column: str) -> bool:
    insp = sa.inspect(bind)
    return column in {c["name"] for c in insp.get_columns(table)}


def upgrade() -> None:
    bind = op.get_bind()
    # 0001 builds the current schema via create_all, so on a fresh DB this column
    # already exists; only add it for older databases that predate it.
    if not _has_column(bind, "cspm_cloud_accounts", "azure_subscription_id"):
        op.add_column(
            "cspm_cloud_accounts",
            sa.Column("azure_subscription_id", sa.String(length=100), nullable=True),
        )


def downgrade() -> None:
    bind = op.get_bind()
    if _has_column(bind, "cspm_cloud_accounts", "azure_subscription_id"):
        op.drop_column("cspm_cloud_accounts", "azure_subscription_id")
