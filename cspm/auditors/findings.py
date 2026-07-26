"""The Finding value object produced by auditor ``check_*`` methods."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field


@dataclass
class Finding:
    """A single audit finding.

    ``check`` is the human title; ``check_id`` is the stable machine id used for
    compliance mapping and dedup. If ``check_id`` is omitted it is derived from
    the title.
    """

    resource: str
    check: str
    severity: str
    remediation: str
    description: str = ""
    check_id: str = ""
    region: str = "global"
    metadata: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.check_id:
            self.check_id = self.check.lower().replace(" ", "_").replace("/", "_")
        if not self.description:
            self.description = self.check

    def dedup_hash(self, cloud_account_id: str) -> str:
        """Stable hash so the same finding on re-scan doesn't duplicate."""
        key = f"{cloud_account_id}|{self.check_id}|{self.resource}"
        return hashlib.sha256(key.encode()).hexdigest()
