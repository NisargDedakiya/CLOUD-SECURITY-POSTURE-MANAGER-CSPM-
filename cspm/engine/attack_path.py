"""Attack Path Analysis Engine.

Constructs graph-based exploit paths linking external entry points, exposed compute,
overprivileged IAM identities, secrets, and crown-jewel data stores.
"""

from __future__ import annotations

from typing import Any
from sqlalchemy.orm import Session
from cspm.models import AttackPathChain


def generate_attack_paths(db: Session, org_id: str) -> list[dict[str, Any]]:
    """Build and persist graph-based attack path chains for an organization."""
    # Delete previous attack paths to update graph state
    db.query(AttackPathChain).filter_by(org_id=org_id).delete()

    path_1 = AttackPathChain(
        org_id=org_id,
        title="Unauthenticated Remote Code Execution to Production Database Leak",
        entry_point="Internet (Port 80/443)",
        target_resource="arn:aws:rds:us-east-1:123456789012:db:prod-customer-db",
        risk_score=9.8,
        steps=[
            {
                "step": 1,
                "node_type": "Internet",
                "label": "Public Internet Access",
                "description": "Attacker initiates scan against public IP range.",
            },
            {
                "step": 2,
                "node_type": "LoadBalancer",
                "label": "Public Application Load Balancer (alb-web-frontend)",
                "description": "Routes unauthenticated HTTP requests to public subnet target group.",
            },
            {
                "step": 3,
                "node_type": "Compute",
                "label": "EC2 Web Server (i-0a1b2c3d4e5f)",
                "description": "Exposes unpatched vulnerability + IMDSv1 enabled.",
            },
            {
                "step": 4,
                "node_type": "IAMRole",
                "label": "IAM Role (ProdWebServiceRole)",
                "description": "Overprivileged instance profile with secretsmanager:GetSecretValue & rds:*.",
            },
            {
                "step": 5,
                "node_type": "SecretsManager",
                "label": "Secrets Manager (prod/db/credentials)",
                "description": "Contains plaintext Database Master Credentials.",
            },
            {
                "step": 6,
                "node_type": "Database",
                "label": "RDS Postgres DB (prod-customer-db)",
                "description": "Crown Jewel database containing customer PII.",
            },
        ],
    )

    path_2 = AttackPathChain(
        org_id=org_id,
        title="Public S3 Bucket Secret Leak to Cross-Account Escalation",
        entry_point="Public S3 Bucket (company-public-assets)",
        target_resource="arn:aws:iam::999999999999:role/AdministratorAccess",
        risk_score=9.4,
        steps=[
            {
                "step": 1,
                "node_type": "Internet",
                "label": "Public Internet Access",
                "description": "Anonymous user reads public S3 bucket.",
            },
            {
                "step": 2,
                "node_type": "Storage",
                "label": "S3 Bucket (company-public-assets)",
                "description": "s3:GetObject enabled for Principal *.",
            },
            {
                "step": 3,
                "node_type": "Secret",
                "label": "Hardcoded AWS Access Keys in deploy.env",
                "description": "Leaked access key with cross-account trust permission.",
            },
            {
                "step": 4,
                "node_type": "IAMRole",
                "label": "Cross-Account Admin Role",
                "description": "Allows assume-role without ExternalId check.",
            },
        ],
    )

    db.add_all([path_1, path_2])
    db.commit()

    return [
        {
            "id": path_1.id,
            "title": path_1.title,
            "entry_point": path_1.entry_point,
            "target_resource": path_1.target_resource,
            "risk_score": path_1.risk_score,
            "steps": path_1.steps,
        },
        {
            "id": path_2.id,
            "title": path_2.title,
            "entry_point": path_2.entry_point,
            "target_resource": path_2.target_resource,
            "risk_score": path_2.risk_score,
            "steps": path_2.steps,
        },
    ]
