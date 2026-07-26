"""Base class and registry for security checks.

Each check is a Python class subclassing :class:`Check`. Checks declare the
resource type they apply to and implement :meth:`evaluate`, returning ``True``
when the resource is compliant. Registration is automatic via ``__init_subclass__``.
"""

from __future__ import annotations

import abc
from typing import Iterable

from cspm.models import Cloud, Finding, Resource, Severity

# Global registry of concrete check classes, keyed by check_id.
_REGISTRY: dict[str, "Check"] = {}


class Check(abc.ABC):
    """A single security posture check for one resource type."""

    #: Stable unique identifier, e.g. "AWS_S3_PUBLIC_ACCESS".
    check_id: str = ""
    #: Human readable title.
    title: str = ""
    #: Which cloud this check applies to.
    cloud: Cloud
    #: Normalized resource type this check evaluates.
    resource_type: str = ""
    #: Severity assigned to a failing finding.
    severity: Severity = Severity.MEDIUM
    #: What the check verifies.
    description: str = ""
    #: How to fix a failing resource.
    remediation: str = ""

    def __init_subclass__(cls, **kwargs: object) -> None:
        super().__init_subclass__(**kwargs)
        # Only register concrete checks that declare an id.
        if getattr(cls, "check_id", ""):
            if cls.check_id in _REGISTRY:
                raise ValueError(f"Duplicate check_id: {cls.check_id}")
            _REGISTRY[cls.check_id] = cls()

    @abc.abstractmethod
    def evaluate(self, resource: Resource) -> bool:
        """Return True if the resource is compliant with this check."""

    def applies_to(self, resource: Resource) -> bool:
        return resource.cloud == self.cloud and resource.type == self.resource_type

    def run(self, resource: Resource) -> Finding:
        compliant = self.evaluate(resource)
        return Finding(
            check_id=self.check_id,
            title=self.title,
            severity=self.severity,
            cloud=resource.cloud,
            resource_id=resource.id,
            resource_type=resource.type,
            region=resource.region,
            description=self.description,
            remediation=self.remediation,
            passed=compliant,
        )


def all_checks() -> list[Check]:
    """Return every registered check instance."""
    return list(_REGISTRY.values())


def checks_for(resource: Resource) -> Iterable[Check]:
    """Yield checks that apply to the given resource."""
    for check in _REGISTRY.values():
        if check.applies_to(resource):
            yield check
