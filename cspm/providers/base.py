"""Provider base class.

A provider is responsible for collecting normalized :class:`Resource` objects
for a single cloud. Real implementations would call the cloud SDK (boto3,
google-cloud, azure-mgmt); the bundled providers ship with a ``mock`` mode so
the tool runs end-to-end without credentials.
"""

from __future__ import annotations

import abc

from cspm.models import Cloud, Resource


class Provider(abc.ABC):
    cloud: Cloud

    def __init__(self, mock: bool = True) -> None:
        self.mock = mock

    @abc.abstractmethod
    def collect(self) -> list[Resource]:
        """Return the normalized resources for this cloud."""

    @abc.abstractmethod
    def _mock_resources(self) -> list[Resource]:
        """Sample resources used when running without credentials."""
