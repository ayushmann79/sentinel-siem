"""Pydantic models for event ingestion and retrieval."""

from datetime import datetime
from typing import Any
from pydantic import BaseModel, Field
import uuid


class RawEventIn(BaseModel):
    """Payload accepted at the /events/ingest endpoint."""
    raw: str = Field(..., description="Raw log line")
    index: str = Field("main", description="Logical index / data stream")
    sourcetype: str = Field("generic", description="Parser hint (syslog, cef, json, windows)")
    source: str | None = None
    host: str | None = None
    ts: datetime | None = Field(None, description="Event timestamp; defaults to now")
    fields: dict[str, Any] | None = None


class BatchIngestIn(BaseModel):
    events: list[RawEventIn] = Field(..., max_length=10_000)


class NormalizedEvent(BaseModel):
    """Fully parsed and enriched event stored in DuckDB."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    ts: datetime
    ingest_ts: datetime = Field(default_factory=datetime.utcnow)
    index: str = "main"
    sourcetype: str = "generic"
    source: str | None = None
    host: str | None = None
    raw: str
    message: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str | None = None
    network_bytes: int | None = None
    username: str | None = None
    process: str | None = None
    pid: int | None = None
    action: str | None = None
    outcome: str | None = None
    severity: int = 0
    fields: dict[str, Any] = Field(default_factory=dict)
    src_country: str | None = None
    src_city: str | None = None
    src_asn: str | None = None
    is_ioc: bool = False
    ioc_type: str | None = None


class EventOut(NormalizedEvent):
    """Response model — same as NormalizedEvent but keeps things explicit."""
    pass


class SearchQuery(BaseModel):
    """Query DSL body for POST /search."""
    query: str = Field("*", description="Search expression")
    index: str | None = None
    sourcetype: str | None = None
    host: str | None = None
    src_ip: str | None = None
    username: str | None = None
    since: str | None = Field("15m", description="Relative time: 15m, 1h, 24h, 7d")
    until: str | None = None
    limit: int = Field(100, ge=1, le=10_000)
    offset: int = Field(0, ge=0)
    sort_by: str = "ts"
    sort_dir: str = "desc"


class SearchResult(BaseModel):
    total: int
    returned: int
    took_ms: float
    events: list[EventOut]
