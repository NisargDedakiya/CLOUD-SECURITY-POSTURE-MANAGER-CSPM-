"""FastAPI application.

In production the CSPM router is included on the shared platform app. This
module provides a standalone app (router + dashboard + health) so the tool can
run on its own in dev, and creates its schema + seeds compliance mappings on
startup.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from cspm import __version__
from cspm.api.router import router
from cspm.compliance import FRAMEWORKS
from cspm.db import SessionLocal, init_db

_WEB_DIR = Path(__file__).resolve().parents[2] / "web"

app = FastAPI(title="Cloud Security Posture Manager", version=__version__)
app.include_router(router)


@app.on_event("startup")
def _startup() -> None:
    init_db()
    from cspm.compliance import seed_mappings

    db = SessionLocal()
    try:
        seed_mappings(db)
    finally:
        db.close()


@app.get("/api/v1/cspm/health")
def health() -> dict:
    return {"status": "ok", "version": __version__, "frameworks": FRAMEWORKS}


if _WEB_DIR.exists():
    app.mount("/static", StaticFiles(directory=_WEB_DIR), name="static")

    @app.get("/")
    def index() -> FileResponse:
        return FileResponse(_WEB_DIR / "index.html")
