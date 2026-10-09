"""Alert management endpoints."""

import json
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query

from sentinelsiem.api.middleware.auth import require_analyst, require_any
from sentinelsiem.database.connection import get_db
from sentinelsiem.models.alert import Alert, AlertStats, AlertStatus, AlertStatusUpdate, Severity
from sentinelsiem.models.user import TokenPayload

router = APIRouter(prefix="/alerts", tags=["Alerts"])

_COLS = [
    "id","created_at","updated_at","rule_id","rule_name","severity","status",
    "mitre_tactic","mitre_technique","description","src_ip","username","host",
    "event_count","first_seen","last_seen","dedup_key","event_ids","analyst","notes"
]


def _row_to_alert(row) -> Alert:
    d = dict(zip(_COLS, row))
    if isinstance(d.get("event_ids"), str):
        d["event_ids"] = json.loads(d["event_ids"])
    return Alert(**d)


@router.get("", response_model=list[Alert])
def list_alerts(
    status: AlertStatus | None = None,
    severity: Severity | None = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    user: TokenPayload = Depends(require_any),
):
    clauses = ["1=1"]
    params  = []
    if status:
        clauses.append("status = ?")
        params.append(status.value)
    if severity:
        clauses.append("severity = ?")
        params.append(severity.value)

    where = " AND ".join(clauses)
    with get_db() as db:
        rows = db.execute(
            f"SELECT {','.join(_COLS)} FROM alerts WHERE {where} ORDER BY created_at DESC LIMIT ? OFFSET ?",
            params + [limit, offset],
        ).fetchall()

    return [_row_to_alert(r) for r in rows]


@router.get("/stats", response_model=AlertStats)
def alert_stats(user: TokenPayload = Depends(require_any)):
    since_24h = datetime.now(timezone.utc) - timedelta(hours=24)
    with get_db() as db:
        total = db.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        last_24h = db.execute("SELECT COUNT(*) FROM alerts WHERE created_at >= ?", [since_24h]).fetchone()[0]
        by_sev = db.execute(
            "SELECT severity, COUNT(*) FROM alerts GROUP BY severity"
        ).fetchall()
        by_status = db.execute(
            "SELECT status, COUNT(*) FROM alerts GROUP BY status"
        ).fetchall()

    return AlertStats(
        total=total,
        last_24h=last_24h,
        by_severity={r[0]: r[1] for r in by_sev},
        by_status={r[0]: r[1] for r in by_status},
    )


@router.get("/{alert_id}", response_model=Alert)
def get_alert(alert_id: str, user: TokenPayload = Depends(require_any)):
    with get_db() as db:
        row = db.execute(
            f"SELECT {','.join(_COLS)} FROM alerts WHERE id = ?", [alert_id]
        ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Alert not found")
    return _row_to_alert(row)


@router.patch("/{alert_id}/status", response_model=Alert)
def update_alert_status(
    alert_id: str,
    body: AlertStatusUpdate,
    user: TokenPayload = Depends(require_analyst),
):
    now = datetime.now(timezone.utc)
    with get_db() as db:
        db.execute(
            "UPDATE alerts SET status=?, analyst=?, notes=?, updated_at=? WHERE id=?",
            [body.status.value, body.analyst or user.sub, body.notes, now, alert_id],
        )
        row = db.execute(
            f"SELECT {','.join(_COLS)} FROM alerts WHERE id = ?", [alert_id]
        ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Alert not found")
    return _row_to_alert(row)
