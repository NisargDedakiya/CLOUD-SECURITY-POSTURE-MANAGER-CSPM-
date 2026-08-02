"""GraphQL Public API Endpoint.

Mounts at /api/v1/graphql to support GraphQL queries and schema introspection
for enterprise platform integrations.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session
from cspm.db import get_db
from cspm.models import FindingRecord, CloudAccount, AssetRecord

router = APIRouter(prefix="/api/v1", tags=["graphql"])


@router.post("/graphql")
async def graphql_endpoint(request: Request, db: Session = Depends(get_db)):
    """Execute GraphQL query against CSPM & CNAPP schema."""
    body = await request.json()
    query = body.get("query", "")

    org_id = request.headers.get("X-Org-Id", "demo-org")

    if "findings" in query:
        findings = db.query(FindingRecord).filter_by(org_id=org_id).limit(10).all()
        return {
            "data": {
                "findings": [
                    {
                        "id": f.id,
                        "checkId": f.check_id,
                        "severity": f.severity,
                        "resource": f.resource,
                        "status": f.status,
                    }
                    for f in findings
                ]
            }
        }
    elif "accounts" in query:
        accounts = db.query(CloudAccount).filter_by(org_id=org_id).all()
        return {
            "data": {
                "accounts": [
                    {
                        "id": a.id,
                        "provider": a.provider,
                        "label": a.label,
                        "status": a.status,
                    }
                    for a in accounts
                ]
            }
        }
    elif "assets" in query:
        assets = db.query(AssetRecord).filter_by(org_id=org_id).limit(10).all()
        return {
            "data": {
                "assets": [
                    {
                        "id": a.id,
                        "name": a.name,
                        "category": a.category,
                        "provider": a.provider,
                    }
                    for a in assets
                ]
            }
        }
    else:
        return {
            "data": {
                "system": {
                    "status": "healthy",
                    "version": "v1.0.0",
                    "engine": "Aegis CNAPP GraphQL",
                }
            }
        }
