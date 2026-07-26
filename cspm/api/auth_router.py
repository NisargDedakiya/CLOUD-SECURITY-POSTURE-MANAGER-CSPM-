"""SCIM 2.0 provisioning + API-key management endpoints.

SCIM lets an IdP (Okta/Azure AD) push user create/deprovision events. This is a
pragmatic subset (Users create/list/get/delete) sufficient for automated
provisioning; it is guarded by a bearer token shared with the IdP.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Header, HTTPException
from sqlalchemy.orm import Session

from cspm.auth.apikeys import create_api_key
from cspm.config import get_settings
from cspm.db import get_db
from cspm.shared.deps import OrgContext, require_role
from cspm.shared.models import ApiKey, OrgMembership, User

_settings = get_settings()

scim_router = APIRouter(prefix="/api/v1/cspm/scim/v2", tags=["scim"])
key_router = APIRouter(prefix="/api/v1/cspm/apikeys", tags=["apikeys"])


def _require_scim(authorization: str | None = Header(default=None)) -> None:
    if not _settings.scim_token:
        raise HTTPException(status_code=501, detail="SCIM not configured.")
    token = authorization[7:].strip() if authorization and authorization.lower().startswith("bearer ") else None
    if token != _settings.scim_token:
        raise HTTPException(status_code=401, detail="Invalid SCIM token.")


def _scim_user(user: User, active: bool = True) -> dict:
    return {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "id": user.id,
        "userName": user.email,
        "active": active,
        "meta": {"resourceType": "User"},
    }


@scim_router.post("/Users", status_code=201)
def scim_create_user(
    payload: dict, _: None = Depends(_require_scim), db: Session = Depends(get_db)
):
    email = payload.get("userName")
    if not email:
        raise HTTPException(status_code=400, detail="userName required.")
    user = db.query(User).filter_by(email=email).one_or_none()
    if user is None:
        user = User(email=email)
        db.add(user)
        db.commit()
        db.refresh(user)
    return _scim_user(user)


@scim_router.get("/Users")
def scim_list_users(_: None = Depends(_require_scim), db: Session = Depends(get_db)):
    users = db.query(User).limit(200).all()
    return {
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": len(users),
        "Resources": [_scim_user(u) for u in users],
    }


@scim_router.delete("/Users/{user_id}", status_code=204)
def scim_deprovision_user(
    user_id: str, _: None = Depends(_require_scim), db: Session = Depends(get_db)
):
    # Deprovision = remove all org memberships (revokes access) per SCIM semantics.
    db.query(OrgMembership).filter_by(user_id=user_id).delete()
    db.commit()


# ---- API keys --------------------------------------------------------------
@key_router.post("", status_code=201)
def create_key(
    payload: dict,
    ctx: OrgContext = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    role = payload.get("role", "analyst")
    if role not in ("viewer", "analyst", "admin"):
        raise HTTPException(status_code=400, detail="Invalid role.")
    record, plaintext = create_api_key(
        db, ctx.org_id, payload.get("name", "api-key"), role
    )
    # Plaintext returned exactly once.
    return {"id": record.id, "prefix": record.prefix, "role": record.role, "key": plaintext}


@key_router.get("")
def list_keys(
    ctx: OrgContext = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    keys = db.query(ApiKey).filter_by(org_id=ctx.org_id, revoked=False).all()
    return [
        {"id": k.id, "name": k.name, "prefix": k.prefix, "role": k.role} for k in keys
    ]


@key_router.delete("/{key_id}", status_code=204)
def revoke_key(
    key_id: str,
    ctx: OrgContext = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    key = db.query(ApiKey).filter_by(id=key_id, org_id=ctx.org_id).one_or_none()
    if key is None:
        raise HTTPException(status_code=404, detail="API key not found.")
    key.revoked = True
    db.commit()
