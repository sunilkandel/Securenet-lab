"""
REST API + web dashboard for SecureNet Lab.

FastAPI app that reads from the same SQLite database the pipeline
writes to. Endpoints:

    GET /                    single-file dashboard (no build step)
    GET /api/stats           summary numbers for the header cards
    GET /api/events          recent events (?limit=, ?ip=)
    GET /api/bans            active firewall bans
    GET /api/alerts          recent alert delivery records
    GET /api/timeseries      events per day (?days=14)
    GET /api/top-attackers   busiest source IPs
    GET /api/health          liveness probe

Run standalone with (binds to API_HOST:API_PORT from config.env):
    python -m src.api.server

The dashboard is one HTML file embedded below on purpose: zero build
tooling, zero npm, works offline. Chart.js loads from a CDN with a
graceful fallback if the monitor VM has no internet.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse, JSONResponse

from src.config import settings
from src.logging_setup import get_logger
from src.storage import Database

log = get_logger(__name__)

app = FastAPI(
    title="SecureNet Lab API",
    description="Read-only API over the SecureNet Lab pipeline database.",
    version="1.0.0",
)

_db: Database | None = None
_db_path: Path | None = None


def configure_database(path: Path | str | None = None) -> None:
    """Point the API at a specific database file.

    Called by tests and by the orchestrator when it wants the API and
    the pipeline to share one explicitly chosen database. Passing None
    restores the value from settings.
    """
    global _db, _db_path
    _db = None
    _db_path = Path(path) if path is not None else None


def get_db() -> Database:
    """Lazily open the shared database (read path only, WAL-safe)."""
    global _db
    if _db is None:
        _db = Database(_db_path or settings.db_path)
    return _db


# ---------------------------------------------------------------------------
# JSON endpoints
# ---------------------------------------------------------------------------

@app.get("/api/health")
def health() -> dict:
    return {"status": "ok", "db": str(settings.db_path)}


@app.get("/api/stats")
def stats() -> dict:
    return get_db().summary()


@app.get("/api/events")
def events(
    limit: int = Query(100, ge=1, le=1000),
    ip: str | None = None,
) -> list[dict]:
    db = get_db()
    rows = db.events_by_ip(ip, limit) if ip else db.recent_events(limit)
    return [e.to_dict() for e in rows]


@app.get("/api/bans")
def bans() -> list[dict]:
    return [b.to_dict() for b in get_db().active_bans()]


@app.get("/api/alerts")
def alerts(limit: int = Query(50, ge=1, le=500)) -> list[dict]:
    return [a.to_dict() for a in get_db().recent_alerts(limit)]


@app.get("/api/timeseries")
def timeseries(days: int = Query(14, ge=1, le=90)) -> list[dict]:
    return get_db().events_per_day(days)


@app.get("/api/top-attackers")
def top_attackers(limit: int = Query(10, ge=1, le=100)) -> list[dict]:
    return get_db().top_attackers(limit)


@app.exception_handler(HTTPException)
async def http_error(request, exc: HTTPException) -> JSONResponse:
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

_DASHBOARD_PATH = Path(__file__).parent / "static" / "dashboard.html"


@app.get("/", response_class=HTMLResponse)
def dashboard() -> HTMLResponse:
    if _DASHBOARD_PATH.exists():
        return HTMLResponse(_DASHBOARD_PATH.read_text(encoding="utf-8"))
    return HTMLResponse(
        "<h1>SecureNet Lab</h1><p>dashboard file missing; "
        "API still available at /api/stats</p>"
    )


def main() -> None:
    import uvicorn

    uvicorn.run(
        app,
        host=settings.api_host,
        port=settings.api_port,
        log_level="debug" if settings.api_debug else "info",
    )


if __name__ == "__main__":
    main()
