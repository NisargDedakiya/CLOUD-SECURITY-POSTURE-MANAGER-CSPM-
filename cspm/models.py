"""Core data models shared across providers, checks, and the engine."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any


class Severity(enum.Enum):
    """Ordered severity levels for findings."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        order = [
            Severity.INFO,
            Severity.LOW,
            Severity.MEDIUM,
            Severity.HIGH,
            Severity.CRITICAL,
        ]
        return order.index(self)

    def __lt__(self, other: "Severity") -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank < other.rank


class Cloud(enum.Enum):
    AWS = "aws"
    GCP = "gcp"
    AZURE = "azure"


@dataclass
class Resource:
    """A normalized cloud resource that checks evaluate.

    ``properties`` holds the provider-specific attributes in a normalized shape
    so checks can be written against a stable structure.
    """

    id: str
    name: str
    type: str
    cloud: Cloud
    region: str = "global"
    properties: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["cloud"] = self.cloud.value
        return data


@dataclass
class Finding:
    """The result of a failed (or informational) check against a resource."""

    check_id: str
    title: str
    severity: Severity
    cloud: Cloud
    resource_id: str
    resource_type: str
    region: str
    description: str
    remediation: str
    passed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "title": self.title,
            "severity": self.severity.value,
            "cloud": self.cloud.value,
            "resource_id": self.resource_id,
            "resource_type": self.resource_type,
            "region": self.region,
            "description": self.description,
            "remediation": self.remediation,
            "passed": self.passed,
        }


@dataclass
class ScanResult:
    """Aggregated output of a scan run."""

    findings: list[Finding] = field(default_factory=list)
    resources_scanned: int = 0
    checks_run: int = 0
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: datetime | None = None

    @property
    def failed(self) -> list[Finding]:
        return [f for f in self.findings if not f.passed]

    @property
    def passed(self) -> list[Finding]:
        return [f for f in self.findings if f.passed]

    def summary(self) -> dict[str, Any]:
        counts: dict[str, int] = {s.value: 0 for s in Severity}
        for f in self.failed:
            counts[f.severity.value] += 1
        by_cloud: dict[str, int] = {}
        for f in self.failed:
            by_cloud[f.cloud.value] = by_cloud.get(f.cloud.value, 0) + 1
        total_checks = len(self.findings)
        passed = len(self.passed)
        score = round((passed / total_checks) * 100, 1) if total_checks else 100.0
        return {
            "resources_scanned": self.resources_scanned,
            "checks_run": self.checks_run,
            "total_findings": len(self.failed),
            "passed_checks": passed,
            "posture_score": score,
            "by_severity": counts,
            "by_cloud": by_cloud,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": self.summary(),
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "findings": [f.to_dict() for f in self.findings],
        }
