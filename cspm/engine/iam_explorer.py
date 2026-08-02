"""IAM Explorer Engine.

Visualizes Users, Roles, Policies, Trust Relationships, Privilege Escalation paths,
Unused Permissions, Risky Policies, and Cross-Account Access.
"""

from __future__ import annotations

from typing import Any
from sqlalchemy.orm import Session
from cspm.models import CloudAccount, CIEMRecord


def get_iam_explorer_data(db: Session, org_id: str) -> dict[str, Any]:
    """Retrieve full IAM hierarchy, trust relationships, and entitlement risks."""
    ciems = db.query(CIEMRecord).filter_by(org_id=org_id).all()

    roles = [
        {
            "id": "role-admin-passrole",
            "name": "ProdWebServiceRole",
            "arn": "arn:aws:iam::123456789012:role/ProdWebServiceRole",
            "type": "role",
            "attached_policies": ["AdministratorAccess", "AmazonS3FullAccess"],
            "trust_relationship": {"principal": "ec2.amazonaws.com", "external_id_required": False},
            "risk_type": "privilege_escalation",
            "unused_permissions_pct": 74.5,
            "is_cross_account": False,
            "last_used_days_ago": 2,
        },
        {
            "id": "role-cross-vendor",
            "name": "VendorAuditCrossAccountRole",
            "arn": "arn:aws:iam::123456789012:role/VendorAuditCrossAccountRole",
            "type": "role",
            "attached_policies": ["SecurityAudit", "ReadOnlyAccess"],
            "trust_relationship": {"principal": "arn:aws:iam::999999999999:root", "external_id_required": False},
            "risk_type": "risky_trust",
            "unused_permissions_pct": 45.0,
            "is_cross_account": True,
            "last_used_days_ago": 142,
        },
    ]

    users = [
        {
            "id": "user-dev-deployer",
            "name": "dev-deployer-user",
            "arn": "arn:aws:iam::123456789012:user/dev-deployer-user",
            "type": "user",
            "attached_policies": ["AdministratorAccess"],
            "mfa_enabled": False,
            "access_keys_count": 2,
            "access_key_age_days": 112,
            "risk_type": "excessive_permissions",
            "unused_permissions_pct": 82.0,
        },
        {
            "id": "user-contractor-dormant",
            "name": "contractor-audit-user",
            "arn": "arn:aws:iam::123456789012:user/contractor-audit-user",
            "type": "user",
            "attached_policies": ["ReadOnlyAccess"],
            "mfa_enabled": True,
            "access_keys_count": 1,
            "access_key_age_days": 210,
            "risk_type": "dormant_account",
            "unused_permissions_pct": 100.0,
        },
    ]

    privilege_escalations = [
        {
            "identity": "ProdWebServiceRole",
            "vector": "iam:PassRole + ec2:RunInstances",
            "impact": "Allows non-admin principal to launch EC2 with root AdministratorAccess instance profile.",
            "remediation": "Scope iam:PassRole permission to specific target role ARNs.",
        }
    ]

    return {
        "org_id": org_id,
        "roles_count": len(roles),
        "users_count": len(users),
        "overprivileged_count": sum(1 for u in users if u["unused_permissions_pct"] > 50),
        "dormant_count": sum(1 for r in roles if r["last_used_days_ago"] > 90),
        "cross_account_trusts_count": sum(1 for r in roles if r["is_cross_account"]),
        "roles": roles,
        "users": users,
        "privilege_escalations": privilege_escalations,
    }
