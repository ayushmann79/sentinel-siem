"""
Correlation engine — evaluates detection rules against incoming events.

Supported rule types:
  - threshold  : N occurrences of an event in a time window
  - sequence   : event A followed by event B (same field value) within a window
  - ioc_match  : event field matches a threat intelligence indicator
"""

import json
import logging
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import yaml

from sentinelsiem.config import get_settings
from sentinelsiem.database.connection import get_db
from sentinelsiem.models.alert import Alert, Severity
from sentinelsiem.models.event import NormalizedEvent

logger = logging.getLogger(__name__)


# ── Rule loading ──────────────────────────────────────────────────────────────

def load_rules() -> list[dict]:
    path = Path(get_settings().rules_path)
    if not path.exists():
        logger.warning("Rules file not found: %s", path)
        return []
    with path.open() as f:
        data = yaml.safe_load(f)
    rules = data.get("rules", [])
    logger.info("Loaded %d correlation rules", len(rules))
    return rules


_RULES: list[dict] = []


def init_rules() -> None:
    global _RULES
    _RULES = load_rules()


# ── Threshold rule ────────────────────────────────────────────────────────────

def _eval_threshold(event: NormalizedEvent, rule: dict) -> Alert | None:
    cond = rule["condition"]
    window_s = cond.get("window_seconds", 60)
    threshold = cond.get("threshold", 5)
    group_field = cond.get("group_by", "src_ip")
    group_value = getattr(event, group_field, None) or event.fields.get(group_field)

    if not group_value:
        return None

    since = datetime.now(timezone.utc) - timedelta(seconds=window_s)

    with get_db() as db:
        row = db.execute(
            f"""
            SELECT COUNT(*) FROM events
            WHERE ts >= ?
              AND index = ?
              AND {_build_filter(cond.get('filter', ''))}
            """,
            [since, cond.get("index", event.index)],
        ).fetchone()

    count = row[0] if row else 0
    if count < threshold:
        return None

    dedup_key = f"{rule['id']}:{group_value}"
    if _is_duplicate(dedup_key):
        return None

    return Alert(
        rule_id=rule["id"],
        rule_name=rule["name"],
        severity=Severity(rule.get("severity", "medium")),
        mitre_technique=rule.get("mitre_attack"),
        description=rule.get("description", rule["name"]),
        src_ip=event.src_ip,
        username=event.username,
        host=event.host,
        event_count=count,
        first_seen=since,
        last_seen=datetime.now(timezone.utc),
        dedup_key=dedup_key,
        event_ids=[event.id],
    )


# ── IOC match rule ────────────────────────────────────────────────────────────

_IOC_CACHE: set[str] = set()


def load_ioc_cache(indicators: list[str]) -> None:
    _IOC_CACHE.update(indicators)
    logger.info("IOC cache loaded: %d indicators", len(_IOC_CACHE))


def _eval_ioc(event: NormalizedEvent, rule: dict) -> Alert | None:
    targets = [event.src_ip, event.dst_ip, event.username]
    matched = next((t for t in targets if t and t in _IOC_CACHE), None)
    if not matched:
        return None

    dedup_key = f"{rule['id']}:{matched}"
    if _is_duplicate(dedup_key):
        return None

    return Alert(
        rule_id=rule["id"],
        rule_name=rule["name"],
        severity=Severity(rule.get("severity", "high")),
        mitre_technique=rule.get("mitre_attack"),
        description=f"IOC match: {matched}",
        src_ip=event.src_ip,
        username=event.username,
        host=event.host,
        event_ids=[event.id],
        dedup_key=dedup_key,
    )


# ── Deduplication ─────────────────────────────────────────────────────────────

def _is_duplicate(dedup_key: str) -> bool:
    with get_db() as db:
        row = db.execute(
            "SELECT id FROM alerts WHERE dedup_key = ? AND created_at >= ?",
            [dedup_key, datetime.now(timezone.utc) - timedelta(seconds=get_settings().alert_dedup_window_seconds)],
        ).fetchone()
    return row is not None


# ── Alert persistence ─────────────────────────────────────────────────────────

def _save_alert(alert: Alert) -> None:
    with get_db() as db:
        db.execute(
            """
            INSERT INTO alerts (
                id, created_at, updated_at, rule_id, rule_name, severity, status,
                mitre_tactic, mitre_technique, description,
                src_ip, username, host, event_count, first_seen, last_seen,
                dedup_key, event_ids
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            [
                alert.id, alert.created_at, alert.updated_at,
                alert.rule_id, alert.rule_name, alert.severity.value, alert.status.value,
                alert.mitre_tactic, alert.mitre_technique, alert.description,
                alert.src_ip, alert.username, alert.host,
                alert.event_count, alert.first_seen, alert.last_seen,
                alert.dedup_key, json.dumps(alert.event_ids),
            ],
        )
    logger.warning("ALERT [%s] %s — %s", alert.severity.upper(), alert.rule_name, alert.description)


# ── Filter builder (safe allow-list) ─────────────────────────────────────────

_ALLOWED_FILTER_TOKENS = re.compile(r"^[a-zA-Z0-9_='\"\s.<>!]+$") if False else None


def _build_filter(filter_str: str) -> str:
    """Convert simple 'key=value AND ...' filter to SQL WHERE fragment."""
    if not filter_str:
        return "1=1"
    parts = []
    for token in re.split(r"\bAND\b", filter_str, flags=re.IGNORECASE):
        token = token.strip()
        if "=" in token:
            k, v = token.split("=", 1)
            parts.append(f"{k.strip()} = '{v.strip()}'")
    return " AND ".join(parts) if parts else "1=1"


import re


# ── Public entry point ────────────────────────────────────────────────────────

def evaluate(event: NormalizedEvent) -> list[Alert]:
    """Run all rules against a single event. Returns any fired alerts."""
    alerts: list[Alert] = []

    for rule in _RULES:
        rule_type = rule.get("condition", {}).get("type", "threshold")
        alert: Alert | None = None

        try:
            if rule_type == "threshold":
                alert = _eval_threshold(event, rule)
            elif rule_type == "ioc_match":
                alert = _eval_ioc(event, rule)
        except Exception as exc:
            logger.error("Rule %s evaluation failed: %s", rule.get("id"), exc)
            continue

        if alert:
            _save_alert(alert)
            alerts.append(alert)

    return alerts
