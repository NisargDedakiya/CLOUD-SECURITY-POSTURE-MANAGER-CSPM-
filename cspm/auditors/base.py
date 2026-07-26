"""Base auditor contract shared by AWS/GCP/Azure engines."""

from __future__ import annotations

import abc

from cspm.auditors.findings import Finding


class BaseAuditor(abc.ABC):
    """A cloud audit engine.

    Concrete auditors implement independently-callable ``check_*`` methods that
    each return ``list[Finding]``. :meth:`run_all` discovers and runs every
    ``check_*`` method and aggregates the results, so the Celery task can invoke
    a single entry point while each check stays unit-testable in isolation.
    """

    provider: str

    def list_checks(self) -> list[str]:
        return sorted(
            name
            for name in dir(self)
            if name.startswith("check_") and callable(getattr(self, name))
        )

    def run_all(self) -> list[Finding]:
        findings: list[Finding] = []
        for name in self.list_checks():
            try:
                findings.extend(getattr(self, name)() or [])
            except Exception as exc:  # noqa: BLE001 - one check must not abort the scan
                findings.append(
                    Finding(
                        resource=self.provider,
                        check=f"{name} failed to execute",
                        check_id=f"{name}_error",
                        severity="info",
                        remediation="Investigate auditor error; verify credentials/permissions.",
                        description=f"{name} raised {type(exc).__name__}: {exc}",
                    )
                )
        return findings

    @abc.abstractmethod
    def resource_snapshots(self) -> dict[str, dict]:
        """Return normalized resource config keyed by resource id, for drift."""
