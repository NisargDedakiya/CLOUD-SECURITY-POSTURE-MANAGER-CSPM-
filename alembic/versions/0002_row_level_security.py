"""Postgres row-level security for tenant isolation.

Enables RLS on every org-scoped CSPM table and adds a policy that restricts rows
to the org id in the ``app.current_org`` session GUC. This is defense-in-depth:
even a missing app-side ``org_id`` filter cannot leak cross-tenant data.

No-op on SQLite (tests) — RLS is Postgres-only.

Revision ID: 0002
Revises: 0001
"""

from __future__ import annotations

from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None

_ORG_TABLES = [
    "cspm_cloud_accounts",
    "cspm_findings",
    "cspm_drift_events",
    "audit_log",
    "org_memberships",
    "cspm_api_keys",
]


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    for table in _ORG_TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"""
            CREATE POLICY {table}_org_isolation ON {table}
            USING (org_id = current_setting('app.current_org', true))
            WITH CHECK (org_id = current_setting('app.current_org', true))
            """
        )


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    for table in _ORG_TABLES:
        op.execute(f"DROP POLICY IF EXISTS {table}_org_isolation ON {table}")
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")
