"""Dashboard metrics and WebSocket live event feed."""

import asyncio
import json
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect

from sentinelsiem.api.middleware.auth import require_any
from sentinelsiem.database.connection import get_db
from sentinelsiem.models.user import TokenPayload

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get("/summary")
def summary(user: TokenPayload = Depends(require_any)):
    since_1h  = datetime.now(timezone.utc) - timedelta(hours=1)
    since_24h = datetime.now(timezone.utc) - timedelta(hours=24)

    with get_db() as db:
        total_events    = db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        events_1h       = db.execute("SELECT COUNT(*) FROM events WHERE ts >= ?", [since_1h]).fetchone()[0]
        events_24h      = db.execute("SELECT COUNT(*) FROM events WHERE ts >= ?", [since_24h]).fetchone()[0]
        open_alerts     = db.execute("SELECT COUNT(*) FROM alerts WHERE status='open'").fetchone()[0]
        critical_alerts = db.execute(
            "SELECT COUNT(*) FROM alerts WHERE status='open' AND severity='critical'"
        ).fetchone()[0]
        unique_hosts    = db.execute("SELECT COUNT(DISTINCT host) FROM events").fetchone()[0]
        unique_sources  = db.execute("SELECT COUNT(DISTINCT sourcetype) FROM events").fetchone()[0]

    return {
        "events": {"total": total_events, "last_1h": events_1h, "last_24h": events_24h},
        "alerts": {"open": open_alerts, "critical_open": critical_alerts},
        "sources": {"unique_hosts": unique_hosts, "unique_sourcetypes": unique_sources},
    }


@router.get("/timeline")
def timeline(user: TokenPayload = Depends(require_any)):
    since_24h = datetime.now(timezone.utc) - timedelta(hours=24)
    with get_db() as db:
        rows = db.execute(
            """
            SELECT date_trunc('hour', ts) as hour, COUNT(*) as cnt
            FROM events
            WHERE ts >= ?
            GROUP BY hour
            ORDER BY hour
            """,
            [since_24h],
        ).fetchall()
    return {"timeline": [{"hour": str(r[0]), "count": r[1]} for r in rows]}


@router.get("/top-sources")
def top_sources(user: TokenPayload = Depends(require_any)):
    with get_db() as db:
        rows = db.execute(
            """
            SELECT host, sourcetype, COUNT(*) as cnt
            FROM events
            GROUP BY host, sourcetype
            ORDER BY cnt DESC
            LIMIT 10
            """
        ).fetchall()
    return {"sources": [{"host": r[0], "sourcetype": r[1], "count": r[2]} for r in rows]}


# ── WebSocket live feed ───────────────────────────────────────────────────────

class _ConnectionManager:
    def __init__(self):
        self._active: list[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self._active.append(ws)

    def disconnect(self, ws: WebSocket):
        self._active = [c for c in self._active if c is not ws]

    async def broadcast(self, message: dict):
        dead = []
        for ws in self._active:
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


_manager = _ConnectionManager()


@router.websocket("/ws/events")
async def ws_events(websocket: WebSocket):
    """Live event feed — polls DuckDB every 2s and pushes new events."""
    await _manager.connect(websocket)
    last_ts = datetime.now(timezone.utc)
    try:
        while True:
            with get_db() as db:
                rows = db.execute(
                    "SELECT id, ts, host, sourcetype, src_ip, action, severity FROM events WHERE ingest_ts > ? ORDER BY ingest_ts DESC LIMIT 20",
                    [last_ts],
                ).fetchall()

            if rows:
                last_ts = datetime.now(timezone.utc)
                for row in rows:
                    await websocket.send_json({
                        "id": row[0], "ts": str(row[1]), "host": row[2],
                        "sourcetype": row[3], "src_ip": row[4],
                        "action": row[5], "severity": row[6],
                    })

            await asyncio.sleep(2)
    except WebSocketDisconnect:
        _manager.disconnect(websocket)
