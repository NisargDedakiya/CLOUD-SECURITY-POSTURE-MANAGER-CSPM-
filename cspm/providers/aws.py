"""AWS provider.

In ``mock`` mode returns sample resources. A real implementation would use
boto3 clients (s3, ec2, iam, rds) to enumerate and normalize resources.
"""

from __future__ import annotations

from cspm.models import Cloud, Resource
from cspm.providers.base import Provider


class AWSProvider(Provider):
    cloud = Cloud.AWS

    def collect(self) -> list[Resource]:
        if self.mock:
            return self._mock_resources()
        return self._collect_live()

    def _collect_live(self) -> list[Resource]:  # pragma: no cover - needs creds
        raise NotImplementedError(
            "Live AWS collection requires boto3 and credentials. "
            "Run with mock=True or implement _collect_live()."
        )

    def _mock_resources(self) -> list[Resource]:
        return [
            Resource(
                id="arn:aws:s3:::public-logs-bucket",
                name="public-logs-bucket",
                type="s3_bucket",
                cloud=Cloud.AWS,
                region="us-east-1",
                properties={
                    "public_access_block": {
                        "block_public_acls": False,
                        "ignore_public_acls": False,
                        "block_public_policy": False,
                        "restrict_public_buckets": False,
                    },
                    "encryption_enabled": False,
                },
            ),
            Resource(
                id="arn:aws:s3:::secure-app-bucket",
                name="secure-app-bucket",
                type="s3_bucket",
                cloud=Cloud.AWS,
                region="us-east-1",
                properties={
                    "public_access_block": {
                        "block_public_acls": True,
                        "ignore_public_acls": True,
                        "block_public_policy": True,
                        "restrict_public_buckets": True,
                    },
                    "encryption_enabled": True,
                },
            ),
            Resource(
                id="sg-0a1b2c3d4e",
                name="web-sg",
                type="security_group",
                cloud=Cloud.AWS,
                region="us-east-1",
                properties={
                    "ingress_rules": [
                        {
                            "from_port": 22,
                            "to_port": 22,
                            "cidr_blocks": ["0.0.0.0/0"],
                        },
                        {
                            "from_port": 443,
                            "to_port": 443,
                            "cidr_blocks": ["0.0.0.0/0"],
                        },
                    ]
                },
            ),
            Resource(
                id="AIDA1EXAMPLE",
                name="alice",
                type="iam_user",
                cloud=Cloud.AWS,
                properties={"console_access": True, "mfa_enabled": False},
            ),
            Resource(
                id="AIDA2EXAMPLE",
                name="ci-bot",
                type="iam_user",
                cloud=Cloud.AWS,
                properties={"console_access": False, "mfa_enabled": False},
            ),
            Resource(
                id="db-prod-1",
                name="prod-postgres",
                type="rds_instance",
                cloud=Cloud.AWS,
                region="us-east-1",
                properties={"storage_encrypted": True},
            ),
        ]
