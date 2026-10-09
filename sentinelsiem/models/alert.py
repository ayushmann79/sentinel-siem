"""Pydantic models for the alert lifecycle."""

from datetime import datetime
from enum import StrEnum
from typing import Any
from pydantic import BaseModel, Field
import uuid


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"


class AlertStatus(StrEnum):
    OPEN            = "open"
    INVESTIGATING   = "investigating"
    CLOSED          = "closed"
    FALSE_POSITIVE  = "false_positive"


class Alert(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    rule_id: str
    rule_name: str
    severity: Severity
    status: AlertStatus = AlertStatus.OPEN
    mitre_tactic: str | None = None
    mitre_technique: str | None = None
    description: str | None = None
    src_ip: str | None = None
    username: str | None = None
    host: str | None = None
    event_count: int = 1
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    dedup_key: str | None = None
    event_ids: list[str] = Field(default_factory=list)
    analyst: str | None = None
    notes: str | None = None


class AlertStatusUpdate(BaseModel):
    status: AlertStatus
    notes: str | None = None
    analyst: str | None = None


class AlertStats(BaseModel):
    total: int
    by_severity: dict[str, int]
    by_status: dict[str, int]
    last_24h: int
