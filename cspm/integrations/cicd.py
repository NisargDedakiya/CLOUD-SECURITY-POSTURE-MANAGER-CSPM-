"""CI/CD Integration & Build Gate Policy Engine.

Evaluates security scan findings against pipeline enforcement thresholds
for GitHub Actions, GitLab CI, Azure DevOps, and Jenkins.
"""

from __future__ import annotations

from typing import Any


def evaluate_pipeline_gate(
    findings: list[dict[str, Any]],
    fail_on_severity: str = "critical",
    max_critical_allowed: int = 0,
    max_high_allowed: int = 2,
) -> dict[str, Any]:
    """Evaluate pipeline status. Fails build if critical or high threshold exceeded."""
    critical_count = sum(1 for f in findings if f.get("severity") == "critical")
    high_count = sum(1 for f in findings if f.get("severity") == "high")
    medium_count = sum(1 for f in findings if f.get("severity") == "medium")

    passed = True
    failure_reasons = []

    if critical_count > max_critical_allowed:
        passed = False
        failure_reasons.append(f"Found {critical_count} Critical finding(s), maximum allowed is {max_critical_allowed}.")

    if high_count > max_high_allowed:
        passed = False
        failure_reasons.append(f"Found {high_count} High finding(s), maximum allowed is {max_high_allowed}.")

    return {
        "status": "passed" if passed else "failed",
        "exit_code": 0 if passed else 1,
        "critical_count": critical_count,
        "high_count": high_count,
        "medium_count": medium_count,
        "failure_reasons": failure_reasons,
        "summary": "CI/CD Security Gate Passed successfully." if passed else "CI/CD Security Gate FAILED — build blocked.",
    }
