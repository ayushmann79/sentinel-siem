"""Search endpoint — translates query DSL to DuckDB SQL."""

import json
import re
import time
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException

from sentinelsiem.api.middleware.auth import require_any
from sentinelsiem.database.connection import get_db
from sentinelsiem.models.event import EventOut, SearchQuery, SearchResult
from sentinelsiem.models.user import TokenPayload

router = APIRouter(prefix="/search", tags=["Search"])

# Relative time parser: "15m" / "1h" / "24h" / "7d"
_TIME_RE = re.compile(r"^(\d+)(m|h|d)$")

_TIME_UNITS = {"m": "minutes", "h": "hours", "d": "days"}

ALLOWED_SORT_FIELDS = {"ts", "ingest_ts", "src_ip", "host", "severity", "username"}
ALLOWED_SORT_DIRS   = {"asc", "desc"}


def _parse_relative(spec: str) -> datetime:
    m = _TIME_RE.match(spec)
    if not m:
        raise HTTPException(status_code=422, detail=f"Invalid time spec: {spec!r}. Use 15m / 1h / 7d")
    value = int(m.group(1))
    unit  = _TIME_UNITS[m.group(2)]
    return datetime.now(timezone.utc) - timedelta(**{unit: value})


def _build_where(q: SearchQuery) -> tuple[str, list]:
    clauses: list[str] = []
    params:  list      = []

    # Time range
    since = _parse_relative(q.since) if q.since else datetime.now(timezone.utc) - timedelta(hours=24)
    clauses.append("ts >= ?")
    params.append(since)
    if q.until:
        clauses.append("ts <= ?")
        params.append(_parse_relative(q.until))

    # Field filters
    if q.index:
        clauses.append("index = ?")
        params.append(q.index)
    if q.sourcetype:
        clauses.append("sourcetype = ?")
        params.append(q.sourcetype)
    if q.host:
        clauses.append("host = ?")
        params.append(q.host)
    if q.src_ip:
        clauses.append("src_ip = ?")
        params.append(q.src_ip)
    if q.username:
        clauses.append("username = ?")
        params.append(q.username)

    # Full-text search on raw / message
    if q.query and q.query != "*":
        # Parse simple key=value pairs, rest is LIKE match
        kv_pattern = re.compile(r"(\w+)=(\S+)")
        remaining = q.query
        for m in kv_pattern.finditer(q.query):
            clauses.append(f"{m.group(1)} = ?")
            params.append(m.group(2))
            remaining = remaining.replace(m.group(0), "").strip()
        if remaining:
            clauses.append("(raw ILIKE ? OR message ILIKE ?)")
            like = f"%{remaining}%"
            params.extend([like, like])

    where = " AND ".join(clauses) if clauses else "1=1"
    return where, params


@router.post("", response_model=SearchResult)
def search(q: SearchQuery, user: TokenPayload = Depends(require_any)):
    if q.sort_by not in ALLOWED_SORT_FIELDS:
        raise HTTPException(status_code=422, detail=f"Invalid sort_by: {q.sort_by}")
    if q.sort_dir not in ALLOWED_SORT_DIRS:
        raise HTTPException(status_code=422, detail="sort_dir must be 'asc' or 'desc'")

    where, params = _build_where(q)
    t0 = time.perf_counter()

    with get_db() as db:
        total = db.execute(f"SELECT COUNT(*) FROM events WHERE {where}", params).fetchone()[0]
        rows = db.execute(
            f"""
            SELECT id, ts, ingest_ts, index, sourcetype, source, host,
                   raw, message, src_ip, dst_ip, src_port, dst_port,
                   protocol, network_bytes, username, process, pid,
                   action, outcome, severity, fields,
                   src_country, src_city, src_asn, is_ioc, ioc_type
            FROM events
            WHERE {where}
            ORDER BY {q.sort_by} {q.sort_dir.upper()}
            LIMIT ? OFFSET ?
            """,
            params + [q.limit, q.offset],
        ).fetchall()

    elapsed = (time.perf_counter() - t0) * 1000
    cols = [
        "id","ts","ingest_ts","index","sourcetype","source","host",
        "raw","message","src_ip","dst_ip","src_port","dst_port",
        "protocol","network_bytes","username","process","pid",
        "action","outcome","severity","fields",
        "src_country","src_city","src_asn","is_ioc","ioc_type"
    ]
    events = []
    for row in rows:
        d = dict(zip(cols, row))
        if isinstance(d.get("fields"), str):
            d["fields"] = json.loads(d["fields"])
        events.append(EventOut(**d))

    return SearchResult(total=total, returned=len(events), took_ms=round(elapsed, 2), events=events)


@router.get("/fields")
def list_fields(user: TokenPayload = Depends(require_any)):
    return {
        "fields": [
            "index","sourcetype","source","host","src_ip","dst_ip",
            "src_port","dst_port","protocol","username","process",
            "action","outcome","severity","is_ioc"
        ]
    }


@router.get("/sourcetypes")
def list_sourcetypes(user: TokenPayload = Depends(require_any)):
    with get_db() as db:
        rows = db.execute(
            "SELECT DISTINCT sourcetype, COUNT(*) as cnt FROM events GROUP BY sourcetype ORDER BY cnt DESC LIMIT 50"
        ).fetchall()
    return {"sourcetypes": [{"name": r[0], "count": r[1]} for r in rows]}
