"""Check package. Importing it registers all built-in checks."""

from cspm.checks import aws_checks, azure_checks, gcp_checks  # noqa: F401
from cspm.checks.base import Check, all_checks, checks_for

__all__ = ["Check", "all_checks", "checks_for"]
