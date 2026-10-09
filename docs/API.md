# SentinelSIEM API Reference

Base URL: `http://localhost:8000`

All endpoints except `/health` and `/auth/login` require:
```
Authorization: Bearer <access_token>
```

---

## Authentication

### POST /auth/login

Obtain a JWT token pair.

**Request**
```json
{ "username": "admin", "password": "SentinelAdmin@2024" }
```

**Response 200**
```json
{
  "access_token": "eyJ...",
  "refresh_token": "eyJ...",
  "token_type": "bearer",
  "expires_in": 1800
}
```

---

## Event Ingestion

### POST /events/ingest

Ingest a single event.

**Request**
```json
{
  "raw": "Jan 10 08:15:32 webserver01 sshd[1234]: Failed password for root from 1.2.3.4 port 22",
  "index": "auth",
  "sourcetype": "syslog",
  "host": "webserver01"
}
```

**Response 201**
```json
{ "event_id": "uuid", "alerts_fired": 0 }
```

### POST /events/ingest/batch

Ingest up to 10,000 events in one request.

**Request**
```json
{
  "events": [
    { "raw": "...", "index": "firewall", "sourcetype": "cef" },
    { "raw": "...", "index": "auth",     "sourcetype": "syslog" }
  ]
}
```

**Response 201**
```json
{ "ingested": 2, "alerts_fired": 0, "first_id": "uuid" }
```

---

## Search

### POST /search

Query events with field filters and full-text search.

**Request**
```json
{
  "query": "Failed password",
  "index": "auth",
  "host": "webserver01",
  "since": "1h",
  "limit": 100,
  "sort_by": "ts",
  "sort_dir": "desc"
}
```

**Response 200**
```json
{
  "total": 42,
  "returned": 42,
  "took_ms": 12.5,
  "events": [ { "id": "...", "ts": "...", "raw": "...", ... } ]
}
```

**Time spec values**: `15m`, `1h`, `6h`, `24h`, `7d`

**Sortable fields**: `ts`, `ingest_ts`, `src_ip`, `host`, `severity`, `username`

---

## Alerts

### GET /alerts

List alerts with optional filtering.

**Query parameters**
| Param | Values |
|-------|--------|
| `status` | `open`, `investigating`, `closed`, `false_positive` |
| `severity` | `critical`, `high`, `medium`, `low`, `info` |
| `limit` | 1–500 (default 50) |
| `offset` | pagination offset |

### PATCH /alerts/{alert_id}/status

Update alert status and add analyst notes.

**Request**
```json
{
  "status": "investigating",
  "analyst": "alice",
  "notes": "Confirmed brute force from Shodan bot — blocking IP at firewall"
}
```

---

## Dashboard

### GET /dashboard/summary

Returns aggregated event counts and alert statistics.

```json
{
  "events":  { "total": 1500000, "last_1h": 4200, "last_24h": 95000 },
  "alerts":  { "open": 12, "critical_open": 2 },
  "sources": { "unique_hosts": 47, "unique_sourcetypes": 8 }
}
```

### WS /ws/events

WebSocket endpoint for live event feed. Pushes new events every 2 seconds.

```
ws://localhost:8000/ws/events
```

Each message:
```json
{ "id": "uuid", "ts": "2024-01-10T08:15:32Z", "host": "webserver01", "src_ip": "1.2.3.4", "action": "failed", "severity": 3 }
```

---

## Error Responses

| Code | Meaning |
|------|---------|
| 401 | Missing or invalid token |
| 403 | Valid token, insufficient role |
| 404 | Resource not found |
| 409 | Conflict (duplicate user) |
| 422 | Validation error — see `detail` in response |
