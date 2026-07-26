"""Runtime configuration.

Values come from environment variables so the tool slots into the shared
platform's 12-factor config. Defaults are safe for local/dev and tests.
"""

from __future__ import annotations

import functools
import os


class Settings:
    """Application settings loaded from the environment."""

    def __init__(self) -> None:
        # Database — Postgres in production, in-memory SQLite for tests/dev.
        self.database_url: str = os.getenv(
            "CSPM_DATABASE_URL", "sqlite+pysqlite:///:memory:"
        )
        # Redis broker shared with the platform Celery app.
        self.redis_url: str = os.getenv("CSPM_REDIS_URL", "redis://localhost:6379/0")
        # AES-256 field-encryption key (base64 urlsafe, 32 bytes). Auto-generated
        # for dev/tests if unset; MUST be provided in production.
        self.encryption_key: str | None = os.getenv("CSPM_ENCRYPTION_KEY")
        # AWS role session name used for STS AssumeRole.
        self.aws_role_session_name: str = os.getenv(
            "CSPM_AWS_SESSION_NAME", "Track2CSPMAudit"
        )
        # Max concurrent cloud API workers per org (throttle protection).
        self.audit_concurrency: int = int(os.getenv("CSPM_AUDIT_CONCURRENCY", "8"))
        # Drift check interval (hours) — informational; scheduling lives in beat.
        self.drift_interval_hours: int = int(os.getenv("CSPM_DRIFT_INTERVAL_HOURS", "6"))


@functools.lru_cache
def get_settings() -> Settings:
    return Settings()
