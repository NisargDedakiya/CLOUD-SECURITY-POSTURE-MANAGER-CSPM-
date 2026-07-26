"""Module 6.4 — Drift Detection."""

from cspm.drift.detector import (
    SECURITY_SENSITIVE_TYPES,
    DriftDiff,
    diff_snapshots,
    is_security_sensitive,
)

__all__ = [
    "DriftDiff",
    "diff_snapshots",
    "is_security_sensitive",
    "SECURITY_SENSITIVE_TYPES",
]
