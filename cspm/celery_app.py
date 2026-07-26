"""Shared Celery app reference (spec 2.3).

In production this object is imported from the platform's ``celery_app`` module
with the four shared queues (critical/high/default/low) already configured.
CSPM registers its tasks against it rather than spawning its own worker.
"""

from __future__ import annotations

from cspm.config import get_settings

try:  # pragma: no cover - celery optional in some dev/test envs
    from celery import Celery
    from kombu import Queue

    _settings = get_settings()
    app = Celery("track2", broker=_settings.redis_url)
    app.conf.task_queues = (
        Queue("critical", routing_key="critical"),
        Queue("high", routing_key="high"),
        Queue("default", routing_key="default"),
        Queue("low", routing_key="low"),
    )
    app.conf.task_default_queue = "default"

    # Scheduled work (Celery Beat): continuous drift + nightly retention purge.
    app.conf.beat_schedule = {
        "drift-sweep": {
            "task": "cspm.scheduled_drift_sweep",
            "schedule": _settings.drift_interval_hours * 3600.0,
            "options": {"queue": "default"},
        },
        "retention-purge": {
            "task": "cspm.retention_purge",
            "schedule": 24 * 3600.0,
            "options": {"queue": "low"},
        },
    }
except Exception:  # noqa: BLE001
    app = None
