"""MSSP (Managed Security Service Provider) Partner Agency Portal Router.

Enables MSSP partners to manage multiple client organizations, configure white-label branding,
and generate client-specific compliance reports.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from cspm.db import get_db
from cspm.models import MSSPClientMapping
from cspm.shared.models import Organisation

router = APIRouter(prefix="/api/v1/mssp", tags=["mssp"])


class MSSPClientCreate(BaseModel):
    client_name: str
    client_slug: str
    branding_logo: str | None = None
    branding_color: str | None = "#00f0ff"


@router.get("/clients")
def list_mssp_clients(db: Session = Depends(get_db)):
    """List all client organizations managed by the MSSP partner."""
    clients = db.query(MSSPClientMapping).all()
    return [
        {
            "id": c.id,
            "mssp_org_id": c.mssp_org_id,
            "client_org_id": c.client_org_id,
            "client_name": c.client_name,
            "branding_logo": c.branding_logo,
            "branding_color": c.branding_color,
            "created_at": c.created_at,
        }
        for c in clients
    ]


@router.post("/clients")
def create_mssp_client(payload: MSSPClientCreate, db: Session = Depends(get_db)):
    """Provision a new client workspace under MSSP agency account."""
    client_org = Organisation(name=payload.client_name, slug=payload.client_slug, plan="pro")
    db.add(client_org)
    db.flush()

    mapping = MSSPClientMapping(
        mssp_org_id="mssp-agency-org",
        client_org_id=client_org.id,
        client_name=payload.client_name,
        branding_logo=payload.branding_logo,
        branding_color=payload.branding_color,
    )
    db.add(mapping)
    db.commit()

    return {
        "status": "created",
        "client_id": mapping.id,
        "client_name": payload.client_name,
        "client_org_id": client_org.id,
    }
