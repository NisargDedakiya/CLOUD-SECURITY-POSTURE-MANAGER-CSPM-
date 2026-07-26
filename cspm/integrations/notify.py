"""Alert dispatch to Slack / webhook / PagerDuty.

``dispatch_alert`` fans an alert out to every configured channel, filtered by a
minimum severity. Delivery is best-effort and never breaks the caller; an
injectable ``sender`` makes it unit-testable without network calls.
"""

from __future__ import annotations

from collections.abc import Callable

from cspm.config import get_settings
from cspm.logging_config import get_logger
from cspm.models import Severity

_log = get_logger("cspm.notify")
_settings = get_settings()

# Default HTTP sender (lazy import so `requests` is optional in tests).
def _http_post(url: str, payload: dict) -> None:  # pragma: no cover - network
    import requests

    requests.post(url, json=payload, timeout=10)


def notifiers_configured() -> list[str]:
    out = []
    if _settings.slack_webhook_url:
        out.append("slack")
    if _settings.generic_webhook_url:
        out.append("webhook")
    if _settings.pagerduty_routing_key:
        out.append("pagerduty")
    return out


def _meets_threshold(severity: str) -> bool:
    try:
        return Severity(severity).rank >= Severity(_settings.alert_min_severity).rank
    except ValueError:
        return False


def _slack_payload(title: str, findings: list[dict]) -> dict:
    lines = [f"• *{f['severity'].upper()}* {f['title']} — `{f['resource']}`" for f in findings[:20]]
    return {"text": f"*{title}* ({len(findings)} finding(s))\n" + "\n".join(lines)}


def _pagerduty_payload(title: str, findings: list[dict]) -> dict:
    top = max((f["severity"] for f in findings), key=lambda s: Severity(s).rank)
    return {
        "routing_key": _settings.pagerduty_routing_key,
        "event_action": "trigger",
        "payload": {
            "summary": f"{title}: {len(findings)} finding(s)",
            "severity": "critical" if top == "critical" else "error",
            "source": "cspm",
        },
    }


def dispatch_alert(
    title: str,
    findings: list[dict],
    sender: Callable[[str, dict], None] = _http_post,
) -> dict:
    """Send an alert for findings at/above the configured severity threshold.

    ``findings`` are dicts with keys: severity, title, resource. Returns a map of
    channel → delivered(bool).
    """
    relevant = [f for f in findings if _meets_threshold(f.get("severity", "info"))]
    results: dict[str, bool] = {}
    if not relevant:
        return results

    channels = {
        "slack": (_settings.slack_webhook_url, _slack_payload(title, relevant)),
        "webhook": (
            _settings.generic_webhook_url,
            {"title": title, "findings": relevant},
        ),
        "pagerduty": (
            "https://events.pagerduty.com/v2/enqueue"
            if _settings.pagerduty_routing_key
            else None,
            _pagerduty_payload(title, relevant),
        ),
    }
    for name, (url, payload) in channels.items():
        if not url:
            continue
        try:
            sender(url, payload)
            results[name] = True
        except Exception:  # noqa: BLE001
            _log.exception("failed to deliver alert to %s", name)
            results[name] = False
    return results
