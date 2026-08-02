"""SCIM 2.0 (System for Cross-domain Identity Management) Provisioning.

Implements standard SCIM endpoints for identity provider synchronization (Okta, Entra ID, Auth0).
"""

from __future__ import annotations

from typing import Any
from sqlalchemy.orm import Session
from cspm.shared.models import SCIMUser


def list_scim_users(db: Session, org_id: str) -> dict[str, Any]:
    """SCIM GET /Users listing."""
    users = db.query(SCIMUser).filter_by(org_id=org_id).all()
    return {
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": len(users),
        "startIndex": 1,
        "itemsPerPage": len(users),
        "Resources": [
            {
                "id": u.id,
                "externalId": u.external_id,
                "userName": u.user_name,
                "emails": [{"value": u.email, "primary": True}],
                "active": u.active,
            }
            for u in users
        ],
    }


def create_scim_user(db: Session, org_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    """SCIM POST /Users creation."""
    ext_id = payload.get("externalId", "ext-user-1")
    username = payload.get("userName", "user@enterprise.com")
    emails = payload.get("emails", [{"value": username}])
    email = emails[0].get("value") if emails else username

    rec = SCIMUser(
        org_id=org_id,
        external_id=ext_id,
        user_name=username,
        email=email,
        active=True,
    )
    db.add(rec)
    db.commit()

    return {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "id": rec.id,
        "externalId": rec.external_id,
        "userName": rec.user_name,
        "emails": [{"value": rec.email, "primary": True}],
        "active": rec.active,
    }
