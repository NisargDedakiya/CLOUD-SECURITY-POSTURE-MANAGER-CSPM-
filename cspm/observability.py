"""Prometheus metrics, Sentry, and OpenTelemetry hooks.

Everything degrades gracefully when the optional libraries or config are absent,
so the core app never hard-depends on them.
"""

from __future__ import annotations

from cspm.config import get_settings
from cspm.logging_config import get_logger

_log = get_logger("cspm.observability")
_settings = get_settings()

try:
    from prometheus_client import Counter, Histogram

    HTTP_REQUESTS = Counter(
        "cspm_http_requests_total", "HTTP requests", ["method", "path", "status"]
    )
    HTTP_LATENCY = Histogram(
        "cspm_http_request_seconds", "HTTP request latency", ["method", "path"]
    )
    SCANS_RUN = Counter("cspm_scans_total", "Audit scans executed", ["provider"])
    FINDINGS_FOUND = Counter(
        "cspm_findings_total", "Findings recorded", ["provider", "severity"]
    )
    _PROM = True
except Exception:  # noqa: BLE001
    _PROM = False


def metrics_available() -> bool:
    return _PROM and _settings.metrics_enabled


def render_metrics() -> tuple[bytes, str]:
    from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

    return generate_latest(), CONTENT_TYPE_LATEST


def observe_request(method: str, path: str, status: int, seconds: float) -> None:
    if not metrics_available():
        return
    HTTP_REQUESTS.labels(method, path, str(status)).inc()
    HTTP_LATENCY.labels(method, path).observe(seconds)


def observe_scan(provider: str) -> None:
    if metrics_available():
        SCANS_RUN.labels(provider).inc()


def init_sentry() -> None:
    """Initialize Sentry error tracking if a DSN is configured."""
    if not _settings.sentry_dsn:
        return
    try:  # pragma: no cover - optional dependency
        import sentry_sdk

        sentry_sdk.init(dsn=_settings.sentry_dsn, traces_sample_rate=0.1)
        _log.info("Sentry initialized")
    except Exception:  # noqa: BLE001
        _log.warning("Sentry DSN set but sentry_sdk not installed")


def init_otel(app) -> None:
    """Instrument FastAPI with OpenTelemetry if the SDK is present."""
    try:  # pragma: no cover - optional dependency
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

        FastAPIInstrumentor.instrument_app(app)
        _log.info("OpenTelemetry instrumentation enabled")
    except Exception:  # noqa: BLE001
        pass
