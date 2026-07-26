"""FastAPI application.

In production the CSPM router is included on the shared platform app. This
module provides a standalone app (router + dashboard + health) so the tool can
run on its own, with logging, request-id tracing, and error handling wired in.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from cspm import __version__
from cspm.api.auth_router import key_router, scim_router
from cspm.api.middleware import (
    RateLimitMiddleware,
    RequestContextMiddleware,
    install_error_handlers,
)
from cspm.api.router import router
from cspm.compliance import FRAMEWORKS
from cspm.db import SessionLocal, init_db
from cspm.logging_config import configure_logging, get_logger
from cspm.observability import init_otel, init_sentry, metrics_available, render_metrics

_WEB_DIR = Path(__file__).resolve().parents[2] / "web"
_log = get_logger("cspm.startup")


@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_logging()
    init_sentry()
    init_db()
    from cspm.compliance import seed_mappings

    db = SessionLocal()
    try:
        inserted = seed_mappings(db)
        _log.info("startup complete; seeded %s compliance mappings", inserted)
    finally:
        db.close()
    yield


app = FastAPI(title="Cloud Security Posture Manager", version=__version__, lifespan=lifespan)
app.add_middleware(RequestContextMiddleware)
app.add_middleware(RateLimitMiddleware)
init_otel(app)
install_error_handlers(app)
app.include_router(router)
app.include_router(scim_router)
app.include_router(key_router)


@app.get("/api/v1/cspm/health")
def health() -> dict:
    return {"status": "ok", "version": __version__, "frameworks": FRAMEWORKS}


@app.get("/metrics")
def metrics():
    from fastapi.responses import Response

    if not metrics_available():
        return Response(status_code=404)
    body, content_type = render_metrics()
    return Response(content=body, media_type=content_type)


@app.get("/api/v1/cspm/ready")
def ready() -> dict:
    """Readiness probe: verifies the DB is reachable."""
    from sqlalchemy import text

    db = SessionLocal()
    try:
        db.execute(text("SELECT 1"))
        return {"status": "ready"}
    finally:
        db.close()


if _WEB_DIR.exists():
    app.mount("/static", StaticFiles(directory=_WEB_DIR), name="static")

    @app.get("/")
    def index() -> FileResponse:
        return FileResponse(_WEB_DIR / "index.html")
