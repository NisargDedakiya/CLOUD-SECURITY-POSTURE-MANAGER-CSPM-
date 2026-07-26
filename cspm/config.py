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

        # ---- Auth / SSO ----------------------------------------------------
        # "headers" (dev trust headers), "secret" (HS256 JWT), or "jwks" (OIDC RS256).
        self.auth_mode: str = os.getenv("CSPM_AUTH_MODE", "headers").lower()
        self.jwt_secret: str | None = os.getenv("CSPM_JWT_SECRET")
        self.oidc_jwks_url: str | None = os.getenv("CSPM_OIDC_JWKS_URL")
        self.oidc_issuer: str | None = os.getenv("CSPM_OIDC_ISSUER")
        self.oidc_audience: str | None = os.getenv("CSPM_OIDC_AUDIENCE")
        # Claim names to read org and roles from the token.
        self.oidc_org_claim: str = os.getenv("CSPM_OIDC_ORG_CLAIM", "org")
        self.oidc_roles_claim: str = os.getenv("CSPM_OIDC_ROLES_CLAIM", "roles")
        # SCIM provisioning bearer token (shared secret with the IdP).
        self.scim_token: str | None = os.getenv("CSPM_SCIM_TOKEN")

        # ---- Secrets management -------------------------------------------
        # "env" (CSPM_ENCRYPTION_KEY), "aws_kms", or "vault".
        self.key_provider: str = os.getenv("CSPM_KEY_PROVIDER", "env").lower()
        self.kms_key_id: str | None = os.getenv("CSPM_KMS_KEY_ID")
        self.vault_addr: str | None = os.getenv("CSPM_VAULT_ADDR")
        self.vault_key_path: str | None = os.getenv("CSPM_VAULT_KEY_PATH")

        # ---- Scale / throttling -------------------------------------------
        self.scan_max_retries: int = int(os.getenv("CSPM_SCAN_MAX_RETRIES", "5"))
        self.scan_backoff_base: float = float(os.getenv("CSPM_SCAN_BACKOFF_BASE", "1.5"))

        # ---- Rate limiting -------------------------------------------------
        self.rate_limit_per_min: int = int(os.getenv("CSPM_RATE_LIMIT_PER_MIN", "120"))

        # ---- Retention (data residency / GDPR) ----------------------------
        self.findings_retention_days: int = int(
            os.getenv("CSPM_FINDINGS_RETENTION_DAYS", "365")
        )
        self.audit_retention_days: int = int(
            os.getenv("CSPM_AUDIT_RETENTION_DAYS", "730")
        )

        # ---- Observability -------------------------------------------------
        self.sentry_dsn: str | None = os.getenv("CSPM_SENTRY_DSN")
        self.metrics_enabled: bool = _get_bool("CSPM_METRICS_ENABLED", default=True)

        # ---- Integrations --------------------------------------------------
        self.slack_webhook_url: str | None = os.getenv("CSPM_SLACK_WEBHOOK_URL")
        self.generic_webhook_url: str | None = os.getenv("CSPM_WEBHOOK_URL")
        self.pagerduty_routing_key: str | None = os.getenv("CSPM_PAGERDUTY_ROUTING_KEY")
        # Minimum severity that triggers an outbound alert.
        self.alert_min_severity: str = os.getenv("CSPM_ALERT_MIN_SEVERITY", "high")

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
        if self.key_provider == "env" and not self.encryption_key:
            problems.append(
                "CSPM_ENCRYPTION_KEY is required in production (or use CSPM_KEY_PROVIDER)."
            )
        if self.database_url.startswith("sqlite"):
            problems.append("CSPM_DATABASE_URL must be Postgres in production.")
        if self.eager_tasks:
            problems.append("CSPM_EAGER_TASKS must be false in production.")
        if self.auth_mode == "headers":
            problems.append("CSPM_AUTH_MODE must be 'secret' or 'jwks' in production.")
        if problems:
            raise ConfigError(" ".join(problems))


@functools.lru_cache
def get_settings() -> Settings:
    return Settings()
