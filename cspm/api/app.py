"""FastAPI application exposing the CSPM scanner and serving the dashboard."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from cspm import __version__
from cspm.checks.base import all_checks
from cspm.engine import ScanEngine
from cspm.models import Cloud

_WEB_DIR = Path(__file__).resolve().parents[2] / "web"

app = FastAPI(
    title="Cloud Security Posture Manager",
    version=__version__,
    description="Multi-cloud (AWS, GCP, Azure) security posture scanning API.",
)


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok", "version": __version__}


@app.get("/api/checks")
def list_checks() -> dict[str, object]:
    checks = [
        {
            "check_id": c.check_id,
            "title": c.title,
            "cloud": c.cloud.value,
            "resource_type": c.resource_type,
            "severity": c.severity.value,
            "description": c.description,
            "remediation": c.remediation,
        }
        for c in all_checks()
    ]
    return {"count": len(checks), "checks": checks}


@app.get("/api/scan")
def scan(
    cloud: list[str] | None = Query(default=None),
    live: bool = Query(default=False),
) -> dict[str, object]:
    try:
        clouds = [Cloud(c.lower()) for c in cloud] if cloud else list(Cloud)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid cloud: {exc}") from exc

    engine = ScanEngine(clouds=clouds, mock=not live)
    try:
        result = engine.scan()
    except NotImplementedError as exc:
        raise HTTPException(status_code=501, detail=str(exc)) from exc
    return result.to_dict()


@app.get("/")
def index() -> FileResponse:
    index_file = _WEB_DIR / "index.html"
    if not index_file.exists():  # pragma: no cover
        raise HTTPException(status_code=404, detail="Dashboard not built.")
    return FileResponse(index_file)


if _WEB_DIR.exists():
    app.mount("/static", StaticFiles(directory=_WEB_DIR), name="static")
