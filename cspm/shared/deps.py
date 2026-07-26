"""Auth / org-context dependencies.

Resolves the caller identity from, in order:
1. ``Authorization: Bearer <api-key>``  (cspm_… keys)
2. ``Authorization: Bearer <jwt>``      (OIDC/JWT from Okta/Azure AD/…)
3. dev trust headers ``X-Org-Id`` / ``X-Role`` (only when CSPM_AUTH_MODE=headers)

Roles come from the token/API key and are cross-checked against the shared
``org_memberships`` table when present (DB-backed RBAC). :func:`require_role`
enforces the role hierarchy on mutating routes.
"""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import Depends, Header, HTTPException, Request
from sqlalchemy.orm import Session

from cspm.config import get_settings
from cspm.db import get_db, set_org_scope

ROLES = ("viewer", "analyst", "admin")
_settings = get_settings()


@dataclass
class OrgContext:
    org_id: str
    user_id: str | None = None
    role: str = "viewer"
    ip_addr: str | None = None
    auth_method: str = "none"


def _highest_role(roles: list[str]) -> str:
    ranked = [r for r in ROLES if r in roles]
    return ranked[-1] if ranked else "viewer"


def _role_from_membership(db: Session, org_id: str, user_id: str | None) -> str | None:
    if not user_id:
        return None
    from cspm.shared.models import OrgMembership

    m = (
        db.query(OrgMembership)
        .filter_by(org_id=org_id, user_id=user_id)
        .one_or_none()
    )
    return m.role if m else None


def get_org_context(
    request: Request,
    db: Session = Depends(get_db),
    authorization: str | None = Header(default=None),
    x_org_id: str | None = Header(default=None),
    x_user_id: str | None = Header(default=None),
    x_role: str | None = Header(default=None),
) -> OrgContext:
    client_ip = request.client.host if request.client else None
    bearer = None
    if authorization and authorization.lower().startswith("bearer "):
        bearer = authorization[7:].strip()

    # 1) API key.
    if bearer and bearer.startswith("cspm_"):
        from cspm.auth.apikeys import verify_api_key

        key = verify_api_key(db, bearer)
        if key is None:
            raise HTTPException(status_code=401, detail="Invalid API key.")
        set_org_scope(db, key.org_id)
        return OrgContext(
            org_id=key.org_id, role=key.role, ip_addr=client_ip, auth_method="api_key"
        )

    # 2) OIDC / JWT.
    if bearer:
        from cspm.auth.tokens import TokenError, verify_token

        try:
            claims = verify_token(bearer)
        except TokenError as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc
        org_id = str(claims.get(_settings.oidc_org_claim, "") or x_org_id or "")
        if not org_id:
            raise HTTPException(status_code=401, detail="Token missing org claim.")
        user_id = str(claims.get("sub", "")) or None
        raw_roles = claims.get(_settings.oidc_roles_claim, []) or []
        if isinstance(raw_roles, str):
            raw_roles = [raw_roles]
        role = _role_from_membership(db, org_id, user_id) or _highest_role(raw_roles)
        set_org_scope(db, org_id)
        return OrgContext(
            org_id=org_id, user_id=user_id, role=role, ip_addr=client_ip, auth_method="jwt"
        )

    # 3) Dev trust headers (only when explicitly enabled).
    if _settings.auth_mode == "headers":
        if not x_org_id:
            raise HTTPException(status_code=401, detail="Missing organisation context.")
        role = (x_role or "admin").lower()
        if role not in ROLES:
            raise HTTPException(status_code=400, detail=f"Unknown role '{role}'.")
        membership_role = _role_from_membership(db, x_org_id, x_user_id)
        set_org_scope(db, x_org_id)
        return OrgContext(
            org_id=x_org_id,
            user_id=x_user_id,
            role=membership_role or role,
            ip_addr=client_ip,
            auth_method="headers",
        )

    raise HTTPException(status_code=401, detail="Authentication required.")


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
