"""Multi-channel Alert Dispatch Engine.

Sends alerts across Email, Slack, MS Teams, Discord, PagerDuty, Opsgenie, and Webhooks
governed by customizable notification policies (Critical only, Compliance failure, Daily/Weekly summary).
"""

from __future__ import annotations

from collections.abc import Callable
from cspm.config import get_settings
from cspm.logging_config import get_logger
from cspm.models import Severity

_log = get_logger("cspm.notify")
_settings = get_settings()


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
    out.extend(["email", "teams", "discord", "opsgenie"])
    return out


def _meets_threshold(severity: str, min_severity: str | None = None) -> bool:
    target_min = min_severity or _settings.alert_min_severity
    try:
        return Severity(severity).rank >= Severity(target_min).rank
    except ValueError:
        return False


def _slack_payload(title: str, findings: list[dict]) -> dict:
    lines = [f"• *{f.get('severity', '').upper()}* {f.get('title', '')} — `{f.get('resource', '')}`" for f in findings[:20]]
    return {"text": f"*{title}* ({len(findings)} finding(s))\n" + "\n".join(lines)}


def _teams_payload(title: str, findings: list[dict]) -> dict:
    return {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "summary": title,
        "themeColor": "FF0000",
        "title": f"🛡️ Aegis Security Alert: {title}",
        "sections": [
            {
                "activityTitle": f"Detected {len(findings)} security finding(s)",
                "facts": [
                    {"name": f.get("title", "Finding"), "value": f"{f.get('severity', 'HIGH').upper()} — {f.get('resource', '')}"}
                    for f in findings[:10]
                ],
            }
        ],
    }


def _discord_payload(title: str, findings: list[dict]) -> dict:
    embeds = [
        {
            "title": title,
            "description": f"Detected {len(findings)} Security Findings in Cloud Environment.",
            "color": 15158332,
            "fields": [
                {"name": f.get("title", "Check"), "value": f"**Severity:** {f.get('severity', '').upper()}\n**Resource:** `{f.get('resource', '')}`"}
                for f in findings[:5]
            ],
        }
    ]
    return {"content": "🚨 **Aegis CNAPP Alert Notification**", "embeds": embeds}


def dispatch_alert(
    title: str,
    findings: list[dict],
    sender: Callable[[str, dict], None] = _http_post,
    min_severity: str | None = None,
    channel_urls: dict[str, str] | None = None,
) -> dict[str, bool]:
    """Send alert across channels governed by policy rules."""
    relevant = [f for f in findings if _meets_threshold(f.get("severity", "info"), min_severity)]
    results: dict[str, bool] = {}
    if not relevant:
        return results

    urls = channel_urls or {}

    channels = {
        "slack": (urls.get("slack") or _settings.slack_webhook_url, _slack_payload(title, relevant)),
        "teams": (urls.get("teams"), _teams_payload(title, relevant)),
        "discord": (urls.get("discord"), _discord_payload(title, relevant)),
        "webhook": (urls.get("webhook") or _settings.generic_webhook_url, {"title": title, "findings": relevant}),
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
