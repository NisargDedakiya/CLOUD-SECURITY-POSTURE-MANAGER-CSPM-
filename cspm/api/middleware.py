"""Request-id, metrics, rate-limiting middleware and error handlers."""

from __future__ import annotations

import time
import uuid
from collections import defaultdict, deque

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from cspm.config import get_settings
from cspm.logging_config import get_logger, request_id_var
from cspm.observability import observe_request

_log = get_logger("cspm.api")
_settings = get_settings()


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Assign/propagate a request id, emit metrics, and log each request."""

    async def dispatch(self, request: Request, call_next):
        rid = request.headers.get("X-Request-Id") or uuid.uuid4().hex[:16]
        token = request_id_var.set(rid)
        start = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception:
            _log.exception("unhandled error %s %s", request.method, request.url.path)
            raise
        finally:
            request_id_var.reset(token)
        elapsed = time.perf_counter() - start
        response.headers["X-Request-Id"] = rid
        # Use the route template (not the raw path) to keep metric cardinality low.
        route = request.scope.get("route")
        path_tmpl = getattr(route, "path", request.url.path)
        observe_request(request.method, path_tmpl, response.status_code, elapsed)
        _log.info("%s %s -> %s (%.0fms)", request.method, request.url.path,
                  response.status_code, elapsed * 1000)
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Simple in-process sliding-window limiter, keyed by client + org.

    Suitable for a single instance; a multi-instance deployment should back this
    with Redis (INCR + EXPIRE). Bypassed for metrics/health probes.
    """

    def __init__(self, app, per_minute: int | None = None) -> None:
        super().__init__(app)
        self.limit = per_minute or _settings.rate_limit_per_min
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if path.endswith(("/health", "/ready", "/metrics")):
            return await call_next(request)
        key = f"{request.client.host if request.client else '-'}|{request.headers.get('X-Org-Id', '-')}"
        now = time.time()
        window = self._hits[key]
        while window and window[0] < now - 60:
            window.popleft()
        if len(window) >= self.limit:
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded.", "limit_per_min": self.limit},
                headers={"Retry-After": "60"},
            )
        window.append(now)
        return await call_next(request)


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception):  # noqa: ANN001
        _log.exception("500 on %s %s", request.method, request.url.path)
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error.", "request_id": request_id_var.get()},
        )
