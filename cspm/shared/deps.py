"""Auth / org-context dependencies.

In production these resolve the JWT and RBAC from the shared ``/api/v1/auth``
backend. Here they provide a minimal, overridable stub: identity comes from
``X-Org-Id`` / ``X-User-Id`` / ``X-Role`` headers (the seam where real JWT/RBAC
is wired in). RBAC is enforced with :func:`require_role`.
"""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import Depends, Header, HTTPException, Request

# Role hierarchy per shared org_memberships.
ROLES = ("viewer", "analyst", "admin")


@dataclass
class OrgContext:
    org_id: str
    user_id: str | None = None
    role: str = "admin"
    ip_addr: str | None = None


def get_org_context(
    request: Request,
    x_org_id: str | None = Header(default=None),
    x_user_id: str | None = Header(default=None),
    x_role: str | None = Header(default=None),
) -> OrgContext:
    if not x_org_id:
        raise HTTPException(status_code=401, detail="Missing organisation context.")
    role = (x_role or "admin").lower()
    if role not in ROLES:
        raise HTTPException(status_code=400, detail=f"Unknown role '{role}'.")
    client_ip = request.client.host if request.client else None
    return OrgContext(org_id=x_org_id, user_id=x_user_id, role=role, ip_addr=client_ip)


def require_role(*allowed: str):
    """RBAC guard: dependency that 403s unless the caller has an allowed role."""

    def _dep(ctx: OrgContext = Depends(get_org_context)) -> OrgContext:
        if allowed and ctx.role not in allowed:
            raise HTTPException(
                status_code=403,
                detail=f"Role '{ctx.role}' not permitted; requires one of {allowed}.",
            )
        return ctx

    return _dep
