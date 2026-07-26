"""Scan engine: collects resources from providers and runs checks against them."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable

from cspm import checks as checks_pkg  # noqa: F401  (ensures checks register)
from cspm.checks.base import checks_for
from cspm.models import Cloud, ScanResult
from cspm.providers import get_provider


class ScanEngine:
    """Runs a full posture scan across the requested clouds."""

    def __init__(self, clouds: Iterable[Cloud] | None = None, mock: bool = True) -> None:
        self.clouds = list(clouds) if clouds is not None else list(Cloud)
        self.mock = mock

    def scan(self) -> ScanResult:
        result = ScanResult(started_at=datetime.now(timezone.utc))
        checks_run = 0
        resources_scanned = 0

        for cloud in self.clouds:
            provider = get_provider(cloud, mock=self.mock)
            for resource in provider.collect():
                resources_scanned += 1
                for check in checks_for(resource):
                    result.findings.append(check.run(resource))
                    checks_run += 1

        result.resources_scanned = resources_scanned
        result.checks_run = checks_run
        result.finished_at = datetime.now(timezone.utc)
        # Sort failing findings first, by severity (most severe first).
        result.findings.sort(key=lambda f: (f.passed, -f.severity.rank))
        return result
