"""Outbound integrations: Slack, webhooks, PagerDuty, Jira."""

from cspm.integrations.notify import dispatch_alert, notifiers_configured

__all__ = ["dispatch_alert", "notifiers_configured"]
