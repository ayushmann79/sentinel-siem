"""Event ingestion and retrieval endpoints."""

import json
from fastapi import APIRouter, Depends, HTTPException

from sentinelsiem.api.middleware.auth import get_current_user, require_analyst, require_any
from sentinelsiem.core.ingestion import ingest_batch, ingest_event
from sentinelsiem.core.correlator import evaluate
from sentinelsiem.database.connection import get_db
from sentinelsiem.models.event import BatchIngestIn, EventOut, RawEventIn
from sentinelsiem.models.user import TokenPayload

router = APIRouter(prefix="/events", tags=["Events"])


class IngestResponse:
    def __init__(self, event_id: str, alerts_fired: int):
        self.event_id = event_id
        self.alerts_fired = alerts_fired


@router.post("/ingest", status_code=201)
def ingest_single(
    body: RawEventIn,
    user: TokenPayload = Depends(require_analyst),
):
    event = ingest_event(body)
    alerts = evaluate(event)
    return {"event_id": event.id, "alerts_fired": len(alerts)}


@router.post("/ingest/batch", status_code=201)
def ingest_batch_endpoint(
    body: BatchIngestIn,
    user: TokenPayload = Depends(require_analyst),
):
    events = ingest_batch(body.events)
    total_alerts = sum(len(evaluate(e)) for e in events)
    return {
        "ingested": len(events),
        "alerts_fired": total_alerts,
        "first_id": events[0].id if events else None,
    }


@router.post("/ingest/syslog", status_code=201)
def ingest_syslog(
    body: dict,
    user: TokenPayload = Depends(require_analyst),
):
    raw = body.get("raw", "")
    if not raw:
        raise HTTPException(status_code=422, detail="'raw' field is required")
    event_in = RawEventIn(raw=raw, sourcetype="syslog", index=body.get("index", "main"))
    event = ingest_event(event_in)
    alerts = evaluate(event)
    return {"event_id": event.id, "alerts_fired": len(alerts)}


@router.get("/{event_id}", response_model=EventOut)
def get_event(
    event_id: str,
    user: TokenPayload = Depends(require_any),
):
    with get_db() as db:
        row = db.execute("SELECT * FROM events WHERE id = ?", [event_id]).fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="Event not found")

    cols = [
        "id","ts","ingest_ts","index","sourcetype","source","host",
        "raw","message","src_ip","dst_ip","src_port","dst_port",
        "protocol","network_bytes","username","process","pid",
        "action","outcome","severity","fields",
        "src_country","src_city","src_asn","is_ioc","ioc_type"
    ]
    d = dict(zip(cols, row))
    if isinstance(d.get("fields"), str):
        d["fields"] = json.loads(d["fields"])
    return EventOut(**d)
