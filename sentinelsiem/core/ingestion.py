"""
Event ingestion pipeline.

Flow: RawEventIn → parse → normalize → enrich → store
"""

import json
import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Sequence

from sentinelsiem.database.connection import get_db
from sentinelsiem.models.event import NormalizedEvent, RawEventIn

logger = logging.getLogger(__name__)

# ── Lightweight parser registry ──────────────────────────────────────────────

def _parse_syslog(raw: str) -> dict:
    """RFC 3164 / 5424 syslog parser."""
    pattern = re.compile(
        r"^(?:<\d+>)?"
        r"(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})?\s*"
        r"(?P<host>\S+)?\s+"
        r"(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?: "
        r"(?P<message>.+)$"
    )
    m = pattern.match(raw)
    if not m:
        return {"message": raw}
    return {k: v for k, v in m.groupdict().items() if v}


def _parse_cef(raw: str) -> dict:
    """ArcSight Common Event Format (CEF) parser."""
    header = re.match(
        r"CEF:(?P<version>\d+)\|(?P<vendor>[^|]*)\|(?P<product>[^|]*)\|"
        r"(?P<dev_version>[^|]*)\|(?P<sig_id>[^|]*)\|(?P<name>[^|]*)\|(?P<severity>[^|]*)\|",
        raw
    )
    if not header:
        return {"message": raw}

    fields: dict = {k: v for k, v in header.groupdict().items() if v}
    ext = raw[header.end():]
    for kv in re.finditer(r"(\w+)=((?:[^\\=\s]|\\.)+)(?:\s|$)", ext):
        fields[kv.group(1)] = kv.group(2)
    return fields


def _parse_json(raw: str) -> dict:
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {"message": raw}


def _parse_windows_event(raw: str) -> dict:
    """Simple Windows Event Log XML extractor."""
    fields: dict = {}
    for key in ("EventID", "Level", "Computer", "Channel", "TimeCreated"):
        m = re.search(rf"<{key}[^>]*>([^<]+)</{key}>", raw)
        if m:
            fields[key.lower()] = m.group(1).strip()
    if not fields:
        fields["message"] = raw
    return fields


_PARSERS = {
    "syslog":  _parse_syslog,
    "cef":     _parse_cef,
    "json":    _parse_json,
    "windows": _parse_windows_event,
}


# ── Field mapping (parser output → NormalizedEvent) ──────────────────────────

_FIELD_MAP = {
    "src":          "src_ip",
    "sourceaddress":"src_ip",
    "spt":          "src_port",
    "dst":          "dst_ip",
    "destinationaddress": "dst_ip",
    "dpt":          "dst_port",
    "act":          "action",
    "outcome":      "outcome",
    "suser":        "username",
    "duser":        "username",
    "app":          "protocol",
    "msg":          "message",
    "process":      "process",
    "pid":          "pid",
    "bytes":        "network_bytes",
}


def _normalize(raw_fields: dict, event_in: RawEventIn) -> NormalizedEvent:
    """Map raw parsed fields to the common schema."""
    mapped: dict = {}
    extra: dict = {}

    for k, v in raw_fields.items():
        target = _FIELD_MAP.get(k.lower(), None)
        if target:
            mapped[target] = v
        else:
            extra[k] = v

    # Prefer explicit fields passed in the request body
    if event_in.fields:
        extra.update(event_in.fields)

    ts = event_in.ts or datetime.now(timezone.utc)

    return NormalizedEvent(
        id=str(uuid.uuid4()),
        ts=ts,
        index=event_in.index,
        sourcetype=event_in.sourcetype,
        source=event_in.source,
        host=event_in.host or mapped.get("host"),
        raw=event_in.raw,
        message=mapped.get("message") or raw_fields.get("message"),
        src_ip=mapped.get("src_ip"),
        dst_ip=mapped.get("dst_ip"),
        src_port=_safe_int(mapped.get("src_port")),
        dst_port=_safe_int(mapped.get("dst_port")),
        protocol=mapped.get("protocol"),
        network_bytes=_safe_int(mapped.get("network_bytes")),
        username=mapped.get("username"),
        process=mapped.get("process"),
        pid=_safe_int(mapped.get("pid")),
        action=mapped.get("action"),
        outcome=mapped.get("outcome"),
        fields=extra,
    )


def _safe_int(val) -> int | None:
    try:
        return int(val) if val is not None else None
    except (ValueError, TypeError):
        return None


# ── Storage ───────────────────────────────────────────────────────────────────

_INSERT_SQL = """
INSERT INTO events (
    id, ts, ingest_ts, index, sourcetype, source, host,
    raw, message, src_ip, dst_ip, src_port, dst_port,
    protocol, network_bytes, username, process, pid,
    action, outcome, severity, fields,
    src_country, src_city, src_asn, is_ioc, ioc_type
) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
"""


def _to_row(e: NormalizedEvent) -> tuple:
    import json as _json
    return (
        e.id, e.ts, e.ingest_ts, e.index, e.sourcetype, e.source, e.host,
        e.raw, e.message, e.src_ip, e.dst_ip, e.src_port, e.dst_port,
        e.protocol, e.network_bytes, e.username, e.process, e.pid,
        e.action, e.outcome, e.severity, _json.dumps(e.fields),
        e.src_country, e.src_city, e.src_asn, e.is_ioc, e.ioc_type,
    )


# ── Public API ────────────────────────────────────────────────────────────────

def ingest_event(event_in: RawEventIn) -> NormalizedEvent:
    parser = _PARSERS.get(event_in.sourcetype.lower(), _parse_syslog)
    raw_fields = parser(event_in.raw)
    normalized = _normalize(raw_fields, event_in)

    with get_db() as db:
        db.execute(_INSERT_SQL, _to_row(normalized))

    return normalized


def ingest_batch(events: Sequence[RawEventIn]) -> list[NormalizedEvent]:
    results: list[NormalizedEvent] = []
    rows: list[tuple] = []

    for ev in events:
        parser = _PARSERS.get(ev.sourcetype.lower(), _parse_syslog)
        raw_fields = parser(ev.raw)
        normalized = _normalize(raw_fields, ev)
        results.append(normalized)
        rows.append(_to_row(normalized))

    with get_db() as db:
        db.executemany(_INSERT_SQL, rows)

    logger.info("Ingested %d events", len(rows))
    return results
