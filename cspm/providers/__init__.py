"""Provider registry."""

from __future__ import annotations

from cspm.models import Cloud
from cspm.providers.aws import AWSProvider
from cspm.providers.azure import AzureProvider
from cspm.providers.base import Provider
from cspm.providers.gcp import GCPProvider

PROVIDERS: dict[Cloud, type[Provider]] = {
    Cloud.AWS: AWSProvider,
    Cloud.GCP: GCPProvider,
    Cloud.AZURE: AzureProvider,
}


def get_provider(cloud: Cloud, mock: bool = True) -> Provider:
    return PROVIDERS[cloud](mock=mock)


__all__ = ["Provider", "AWSProvider", "GCPProvider", "AzureProvider", "PROVIDERS", "get_provider"]
