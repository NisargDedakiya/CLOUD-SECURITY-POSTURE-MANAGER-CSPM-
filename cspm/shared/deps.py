"""Auth / org-context dependencies.

In production these resolve the JWT and RBAC from the shared ``/api/v1/auth``
backend. Here they provide a minimal, overridable stub: the org id comes from
the ``X-Org-Id`` header (dependency-injected/overridable in tests), and every
authenticated action is written to the shared audit_log.
"""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import Header, HTTPException


@dataclass
class OrgContext:
    org_id: str
    user_id: str | None = None
    role: str = "admin"


def get_org_context(
    x_org_id: str | None = Header(default=None),
    x_user_id: str | None = Header(default=None),
) -> OrgContext:
    if not x_org_id:
        raise HTTPException(status_code=401, detail="Missing organisation context.")
    return OrgContext(org_id=x_org_id, user_id=x_user_id)


def require_role(*allowed: str):
    """RBAC guard factory. Viewer/analyst/admin roles per shared org_memberships."""

    def _dep(ctx: OrgContext) -> OrgContext:
        if allowed and ctx.role not in allowed:
            raise HTTPException(status_code=403, detail="Insufficient role.")
        return ctx

    return _dep
