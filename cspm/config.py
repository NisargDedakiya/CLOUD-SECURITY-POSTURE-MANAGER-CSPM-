"""Runtime configuration.

Values come from environment variables so the tool slots into the shared
platform's 12-factor config. Defaults are safe for local/dev and tests; in
production (``CSPM_ENV=production``) missing critical secrets fail fast.
"""

from __future__ import annotations

import functools
import os


class ConfigError(RuntimeError):
    """Raised when the configuration is invalid for the current environment."""


def _get_bool(name: str, default: bool) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    return val.strip().lower() in {"1", "true", "yes", "on"}


class Settings:
    """Application settings loaded from the environment."""

    def __init__(self) -> None:
        self.env: str = os.getenv("CSPM_ENV", "development").lower()

        # Database — Postgres in production, in-memory SQLite for tests/dev.
        self.database_url: str = os.getenv(
            "CSPM_DATABASE_URL", "sqlite+pysqlite:///:memory:"
        )
        # Redis broker shared with the platform Celery app.
        self.redis_url: str = os.getenv("CSPM_REDIS_URL", "redis://localhost:6379/0")
        # AES-256 field-encryption key (base64 urlsafe, 32 bytes).
        self.encryption_key: str | None = os.getenv("CSPM_ENCRYPTION_KEY")
        # Run scans synchronously in-request (dev/test) instead of via Celery.
        self.eager_tasks: bool = _get_bool("CSPM_EAGER_TASKS", default=True)

        # STS / audit tuning.
        self.aws_role_session_name: str = os.getenv(
            "CSPM_AWS_SESSION_NAME", "Track2CSPMAudit"
        )
        self.audit_concurrency: int = int(os.getenv("CSPM_AUDIT_CONCURRENCY", "8"))
        self.drift_interval_hours: int = int(os.getenv("CSPM_DRIFT_INTERVAL_HOURS", "6"))

        # Logging.
        self.log_level: str = os.getenv("CSPM_LOG_LEVEL", "INFO").upper()
        self.json_logs: bool = _get_bool("CSPM_JSON_LOGS", default=self.is_production)

        # Pagination bounds.
        self.default_page_size: int = int(os.getenv("CSPM_PAGE_SIZE", "50"))
        self.max_page_size: int = int(os.getenv("CSPM_MAX_PAGE_SIZE", "200"))

        self._validate()

    @property
    def is_production(self) -> bool:
        return self.env in {"production", "prod", "staging"}

    def _validate(self) -> None:
        if not self.is_production:
            return
        problems = []
        if not self.encryption_key:
            problems.append("CSPM_ENCRYPTION_KEY is required in production.")
        if self.database_url.startswith("sqlite"):
            problems.append("CSPM_DATABASE_URL must be Postgres in production.")
        if self.eager_tasks:
            problems.append("CSPM_EAGER_TASKS must be false in production.")
        if problems:
            raise ConfigError(" ".join(problems))


@functools.lru_cache
def get_settings() -> Settings:
    return Settings()
