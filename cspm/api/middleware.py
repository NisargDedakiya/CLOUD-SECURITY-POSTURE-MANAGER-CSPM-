"""Request-id middleware and global exception handlers."""

from __future__ import annotations

import uuid

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from cspm.logging_config import get_logger, request_id_var

_log = get_logger("cspm.api")


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Assign/propagate a request id and log each request outcome."""

    async def dispatch(self, request: Request, call_next):
        rid = request.headers.get("X-Request-Id") or uuid.uuid4().hex[:16]
        token = request_id_var.set(rid)
        try:
            response = await call_next(request)
        except Exception:
            _log.exception("unhandled error %s %s", request.method, request.url.path)
            raise
        finally:
            request_id_var.reset(token)
        response.headers["X-Request-Id"] = rid
        _log.info(
            "%s %s -> %s", request.method, request.url.path, response.status_code
        )
        return response


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception):  # noqa: ANN001
        _log.exception("500 on %s %s", request.method, request.url.path)
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error.", "request_id": request_id_var.get()},
        )
