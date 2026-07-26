"""Prowler adapter — ingest Prowler's findings for check breadth.

Rather than hand-writing 1000+ checks, an org can run `prowler` (an open-source
scanner with deep CIS/SOC2/PCI coverage) and CSPM ingests its OCSF/JSON output,
normalizing each result into a CSPM :class:`Finding`. This runs alongside the
native auditors, giving both curated depth and broad coverage.
"""

from __future__ import annotations

import json
import shutil
import subprocess  # noqa: S404 - invoking the prowler CLI is the intended use

from cspm.auditors.findings import Finding
from cspm.logging_config import get_logger

_log = get_logger("cspm.prowler")

# Prowler severity strings → CSPM severities.
_SEV = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "info",
}


def prowler_available() -> bool:
    return shutil.which("prowler") is not None


def parse_prowler_json(data: list[dict]) -> list[Finding]:
    """Normalize Prowler JSON (list of check results) into Findings.

    Only FAIL results become findings. Handles both the native and OCSF shapes.
    """
    findings: list[Finding] = []
    for item in data:
        status = (item.get("status") or item.get("status_code") or "").upper()
        if status not in {"FAIL", "FAILED"}:
            continue
        check_id = item.get("check_id") or item.get("finding_uid") or "prowler_check"
        severity = _SEV.get(str(item.get("severity", "medium")).lower(), "medium")
        resource = (
            item.get("resource_uid")
            or item.get("resource_arn")
            or item.get("resource_id")
            or "unknown"
        )
        findings.append(
            Finding(
                resource=resource,
                check=item.get("check_title") or check_id,
                check_id=f"prowler_{check_id}",
                severity=severity,
                remediation=(
                    item.get("remediation", {}).get("recommendation", {}).get("text")
                    if isinstance(item.get("remediation"), dict)
                    else item.get("remediation_recommendation_text", "")
                )
                or "See Prowler remediation guidance.",
                description=item.get("status_extended") or item.get("check_title") or "",
                metadata={"source": "prowler"},
            )
        )
    return findings


def run_prowler(provider: str = "aws", extra_args: list[str] | None = None) -> list[Finding]:  # pragma: no cover - needs prowler + creds
    """Run the prowler CLI and return normalized findings."""
    if not prowler_available():
        raise RuntimeError("prowler CLI not installed.")
    cmd = ["prowler", provider, "-M", "json-ocsf", "--output-file", "/tmp/prowler"]  # noqa: S108
    cmd += extra_args or []
    _log.info("running prowler: %s", " ".join(cmd))
    subprocess.run(cmd, check=False, capture_output=True)  # noqa: S603
    with open("/tmp/prowler.ocsf.json") as fh:  # noqa: S108
        return parse_prowler_json(json.load(fh))
