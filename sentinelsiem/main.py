"""
SentinelSIEM — application entry point.

Start with: python -m sentinelsiem.main
or via Docker: the CMD in Dockerfile calls this module.
"""

import logging
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone

import uvicorn
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from sentinelsiem.api.middleware.auth import hash_password
from sentinelsiem.api.routes import alerts, auth, dashboard, events, search
from sentinelsiem.config import get_settings
from sentinelsiem.core.correlator import init_rules
from sentinelsiem.database.connection import close_db, get_db

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s — %(message)s",
)
logger = logging.getLogger("sentinelsiem")
settings = get_settings()


# ── Startup / shutdown ────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting SentinelSIEM v%s (%s)", settings.app_version, settings.app_env)
    _ensure_admin_user()
    init_rules()
    yield
    close_db()
    logger.info("SentinelSIEM stopped")


def _ensure_admin_user() -> None:
    """Create the default admin account on first boot."""
    with get_db() as db:
        exists = db.execute(
            "SELECT id FROM users WHERE username = ?", [settings.admin_username]
        ).fetchone()
        if not exists:
            db.execute(
                "INSERT INTO users (id, created_at, username, email, password_hash, role) VALUES (?,?,?,?,?,?)",
                [
                    str(uuid.uuid4()),
                    datetime.now(timezone.utc),
                    settings.admin_username,
                    settings.admin_email,
                    hash_password(settings.admin_password),
                    "admin",
                ],
            )
            logger.info("Admin user created: %s", settings.admin_username)


# ── App factory ───────────────────────────────────────────────────────────────

app = FastAPI(
    title="SentinelSIEM",
    description="Enterprise Security Information & Event Management platform",
    version=settings.app_version,
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API routers
app.include_router(auth.router)
app.include_router(events.router)
app.include_router(search.router)
app.include_router(alerts.router)
app.include_router(dashboard.router)

# Static frontend
try:
    app.mount("/static", StaticFiles(directory="frontend/static"), name="static")
except Exception:
    pass


# ── Utility endpoints ─────────────────────────────────────────────────────────

@app.get("/health", tags=["System"])
def health():
    return {"status": "ok", "version": settings.app_version, "env": settings.app_env}


@app.get("/metrics", tags=["System"])
def metrics():
    with get_db() as db:
        event_count = db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        alert_count = db.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    return {"events_total": event_count, "alerts_total": alert_count}


@app.get("/", include_in_schema=False)
def root():
    try:
        return FileResponse("frontend/index.html")
    except Exception:
        return JSONResponse({"message": "SentinelSIEM API", "docs": "/docs"})


# ── Run ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    uvicorn.run(
        "sentinelsiem.main:app",
        host=settings.app_host,
        port=settings.app_port,
        reload=not settings.is_production,
        log_level=settings.log_level.lower(),
    )
