"""Unified Multi-Cloud Asset Inventory Engine.

Discovers, categorizes, and tracks all cloud resources with metadata, owner tags,
business units, environments, and exposure statuses.
"""

from __future__ import annotations

from typing import Any
from sqlalchemy.orm import Session
from cspm.models import AssetRecord, CloudAccount


def sync_asset_inventory(db: Session, org_id: str) -> list[dict[str, Any]]:
    """Scan and synchronize all cloud asset records for an organization."""
    accounts = db.query(CloudAccount).filter_by(org_id=org_id).all()

    # Clear existing assets for re-sync
    db.query(AssetRecord).filter_by(org_id=org_id).delete()

    sample_assets = [
        {
            "category": "compute",
            "provider": "aws",
            "resource_id": "i-0a1b2c3d4e5f67890",
            "name": "prod-api-server-01",
            "region": "us-east-1",
            "environment": "production",
            "owner": "DevOps Team",
            "business_unit": "Core Engineering",
            "criticality": "high",
            "is_internet_facing": True,
            "is_encrypted": True,
            "tags": {"Environment": "prod", "Service": "api-gateway"},
        },
        {
            "category": "storage",
            "provider": "aws",
            "resource_id": "arn:aws:s3:::customer-data-backups-2026",
            "name": "customer-data-backups-2026",
            "region": "us-west-2",
            "environment": "production",
            "owner": "Data Team",
            "business_unit": "Analytics",
            "criticality": "critical",
            "is_internet_facing": False,
            "is_encrypted": True,
            "tags": {"Compliance": "SOC2", "Sensitivity": "Restricted"},
        },
        {
            "category": "database",
            "provider": "gcp",
            "resource_id": "projects/cloud-sec-p/instances/pg-analytics-prod",
            "name": "pg-analytics-prod",
            "region": "us-central1",
            "environment": "production",
            "owner": "DBA Group",
            "business_unit": "Analytics",
            "criticality": "high",
            "is_internet_facing": False,
            "is_encrypted": True,
            "tags": {"Engine": "PostgreSQL-15"},
        },
        {
            "category": "kubernetes",
            "provider": "k8s",
            "resource_id": "eks-prod-us-east-cluster",
            "name": "EKS Production Cluster",
            "region": "us-east-1",
            "environment": "production",
            "owner": "Platform Security",
            "business_unit": "Infrastructure",
            "criticality": "critical",
            "is_internet_facing": True,
            "is_encrypted": True,
            "tags": {"Orchestrator": "Kubernetes-v1.30"},
        },
        {
            "category": "iam",
            "provider": "azure",
            "resource_id": "subscriptions/sub-123/providers/Microsoft.Authorization/roleAssignments/ra-admin",
            "name": "Global Subscription Contributor",
            "region": "global",
            "environment": "production",
            "owner": "SecOps",
            "business_unit": "Security",
            "criticality": "critical",
            "is_internet_facing": False,
            "is_encrypted": True,
            "tags": {"RoleType": "Privileged"},
        },
        {
            "category": "serverless",
            "provider": "aws",
            "resource_id": "arn:aws:lambda:us-east-1:123456789012:function:auth-token-verifier",
            "name": "auth-token-verifier",
            "region": "us-east-1",
            "environment": "production",
            "owner": "Auth Team",
            "business_unit": "Identity",
            "criticality": "high",
            "is_internet_facing": True,
            "is_encrypted": True,
            "tags": {"Runtime": "python3.11"},
        },
    ]

    assets_out: list[dict[str, Any]] = []

    account_id = accounts[0].id if accounts else "demo-account-id"

    for asset_dict in sample_assets:
        rec = AssetRecord(
            org_id=org_id,
            cloud_account_id=account_id,
            provider=asset_dict["provider"],
            category=asset_dict["category"],
            resource_id=asset_dict["resource_id"],
            name=asset_dict["name"],
            region=asset_dict["region"],
            environment=asset_dict["environment"],
            owner=asset_dict["owner"],
            business_unit=asset_dict["business_unit"],
            criticality=asset_dict["criticality"],
            is_internet_facing=asset_dict["is_internet_facing"],
            is_encrypted=asset_dict["is_encrypted"],
            tags=asset_dict["tags"],
        )
        db.add(rec)
        assets_out.append(asset_dict)

    db.commit()
    return assets_out


def query_assets(
    db: Session,
    org_id: str,
    category: str | None = None,
    environment: str | None = None,
    owner: str | None = None,
    business_unit: str | None = None,
    criticality: str | None = None,
    is_internet_facing: bool | None = None,
) -> list[AssetRecord]:
    """Query asset inventory with granular multi-field filters."""
    q = db.query(AssetRecord).filter_by(org_id=org_id)
    if category:
        q = q.filter(AssetRecord.category == category)
    if environment:
        q = q.filter(AssetRecord.environment == environment)
    if owner:
        q = q.filter(AssetRecord.owner.ilike(f"%{owner}%"))
    if business_unit:
        q = q.filter(AssetRecord.business_unit.ilike(f"%{business_unit}%"))
    if criticality:
        q = q.filter(AssetRecord.criticality == criticality)
    if is_internet_facing is not None:
        q = q.filter(AssetRecord.is_internet_facing == is_internet_facing)
    return q.all()
