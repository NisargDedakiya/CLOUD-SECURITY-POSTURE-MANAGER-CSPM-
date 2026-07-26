"""GCP provider (mock mode ships sample resources)."""

from __future__ import annotations

from cspm.models import Cloud, Resource
from cspm.providers.base import Provider


class GCPProvider(Provider):
    cloud = Cloud.GCP

    def collect(self) -> list[Resource]:
        if self.mock:
            return self._mock_resources()
        return self._collect_live()

    def _collect_live(self) -> list[Resource]:  # pragma: no cover - needs creds
        raise NotImplementedError(
            "Live GCP collection requires google-cloud SDK and credentials."
        )

    def _mock_resources(self) -> list[Resource]:
        return [
            Resource(
                id="projects/demo/buckets/public-assets",
                name="public-assets",
                type="storage_bucket",
                cloud=Cloud.GCP,
                properties={
                    "iam_members": ["allUsers"],
                    "uniform_bucket_level_access": False,
                },
            ),
            Resource(
                id="projects/demo/buckets/internal-data",
                name="internal-data",
                type="storage_bucket",
                cloud=Cloud.GCP,
                properties={
                    "iam_members": ["user:ops@demo.com"],
                    "uniform_bucket_level_access": True,
                },
            ),
            Resource(
                id="projects/demo/firewalls/allow-rdp",
                name="allow-rdp",
                type="firewall_rule",
                cloud=Cloud.GCP,
                properties={
                    "direction": "INGRESS",
                    "source_ranges": ["0.0.0.0/0"],
                    "allowed": [{"protocol": "tcp", "ports": ["3389"]}],
                },
            ),
            Resource(
                id="projects/demo/instances/web-1",
                name="web-1",
                type="compute_instance",
                cloud=Cloud.GCP,
                region="us-central1",
                properties={"has_public_ip": True},
            ),
            Resource(
                id="projects/demo/serviceAccounts/deploy@demo.iam",
                name="deploy",
                type="service_account",
                cloud=Cloud.GCP,
                properties={"keys": [{"age_days": 120}, {"age_days": 10}]},
            ),
        ]
