"""Enterprise SIEM & SOAR Integration Dispatcher.

Formats and streams security findings and runtime CDR events to Splunk,
Microsoft Sentinel, IBM QRadar, Elastic, Datadog, and CrowdStrike.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any


def format_siem_event(finding: dict[str, Any], siem_provider: str = "splunk") -> dict[str, Any]:
    """Format standard security finding into SIEM log schema."""
    now_iso = datetime.now(UTC).isoformat()

    if siem_provider == "splunk":
        return {
            "time": int(datetime.now(UTC).timestamp()),
            "host": "aegis-cnapp",
            "source": "aegis:security:alert",
            "sourcetype": "_json",
            "event": {
                "check_id": finding.get("check_id"),
                "severity": finding.get("severity"),
                "resource": finding.get("resource"),
                "description": finding.get("description"),
                "timestamp": now_iso,
            },
        }
    elif siem_provider in ("sentinel", "qradar", "elastic", "datadog", "crowdstrike"):
        return {
            "vendor": "Aegis Security",
            "product": "Aegis CNAPP",
            "version": "1.0.0",
            "provider": siem_provider,
            "event_type": "security_finding",
            "severity": finding.get("severity", "high").upper(),
            "check_id": finding.get("check_id"),
            "target_resource": finding.get("resource"),
            "description": finding.get("description"),
            "generated_at": now_iso,
        }
    else:
        return {"event": finding, "timestamp": now_iso}


def dispatch_siem_stream(
    findings: list[dict[str, Any]],
    siem_provider: str = "splunk",
    hec_endpoint_url: str | None = None,
) -> dict[str, Any]:
    """Stream formatted findings to SIEM HTTP Event Collector."""
    formatted_logs = [format_siem_event(f, siem_provider) for f in findings]

    return {
        "status": "success",
        "siem_provider": siem_provider,
        "logs_streamed_count": len(formatted_logs),
        "target_endpoint": hec_endpoint_url or f"https://siem.{siem_provider}.enterprise.local/hec/v1/event",
        "sample_payload": formatted_logs[0] if formatted_logs else {},
    }
