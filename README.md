# SentinelSIEM

> Enterprise-grade Security Information & Event Management platform built with Python, FastAPI, and DuckDB.

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-green.svg)](https://fastapi.tiangolo.com)
[![DuckDB](https://img.shields.io/badge/DuckDB-0.9+-yellow.svg)](https://duckdb.org)
[![Docker](https://img.shields.io/badge/Docker-ready-blue.svg)](https://docker.com)
[![Tests](https://img.shields.io/badge/Tests-64%20passing-brightgreen.svg)]()
[![License](https://img.shields.io/badge/License-MIT-purple.svg)](LICENSE)

---

## Overview

SentinelSIEM is a full-stack SIEM platform designed for real-time log ingestion, threat correlation, and security analytics. It supports multi-source event ingestion, rule-based and ML-assisted alerting, structured search via a REST API, and a real-time dashboard — all deployable in minutes via Docker.

### Key Capabilities

- **Universal log ingestion** — accepts Syslog, CEF, JSON, Windows Event Log, and raw text
- **Real-time event parsing** — pluggable parser pipeline with field normalization (ECS-aligned schema)
- **Threat correlation engine** — threshold rules, sequence detection, and IOC matching
- **Fast analytics** — DuckDB columnar storage with sub-second query response on millions of events
- **REST API** — 23 documented endpoints with JWT authentication and role-based access
- **Live dashboard** — WebSocket-powered real-time event feed and metrics
- **Docker-first** — single `docker compose up` to get a fully running stack

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Data Sources                         │
│     Syslog · Windows Events · APIs · Firewalls · EDR        │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                   Ingestion Layer                            │
│     Multi-format receiver → Parser pipeline → Enrichment    │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                 Correlation Engine                           │
│     Threshold rules · Sequence detection · IOC matching     │
└────────┬────────────────────────────────────────────────────┘
         │                              │
         ▼                              ▼
┌─────────────────┐           ┌──────────────────┐
│   DuckDB Store  │           │   Alert Engine   │
│  Columnar OLAP  │           │  Dedup · Triage  │
└─────────────────┘           └──────────────────┘
         │                              │
         ▼                              ▼
┌─────────────────────────────────────────────────────────────┐
│                     FastAPI Layer                            │
│        JWT Auth · RBAC · REST API · WebSocket feed          │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                     Frontend                                 │
│          Dashboard · Search · Alert Console                  │
└─────────────────────────────────────────────────────────────┘
```

---

## Quick Start

### Prerequisites

- Docker 24+ and Docker Compose v2
- Python 3.11+ (for local development)

### Run with Docker (recommended)

```bash
git clone https://github.com/ayushmann79/sentinelsiem.git
cd sentinelsiem
cp .env.example .env
docker compose up -d
```

The stack starts at:
- **Dashboard** → http://localhost:8000
- **API docs** → http://localhost:8000/docs
- **Health check** → http://localhost:8000/health

Default credentials: `admin / SentinelAdmin@2024`

### Run locally

```bash
git clone https://github.com/ayushmann79/sentinelsiem.git
cd sentinelsiem

python -m venv venv
source venv/bin/activate       # Windows: venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env
python -m sentinelsiem.main
```

---

## Project Structure

```
sentinelsiem/
├── sentinelsiem/
│   ├── main.py                  # FastAPI application entry point
│   ├── config.py                # Settings (Pydantic BaseSettings)
│   ├── api/
│   │   ├── routes/
│   │   │   ├── auth.py          # Login, token refresh, user management
│   │   │   ├── events.py        # Event ingestion and retrieval
│   │   │   ├── search.py        # Query DSL endpoint
│   │   │   ├── alerts.py        # Alert management
│   │   │   └── dashboard.py     # Metrics and WebSocket feed
│   │   └── middleware/
│   │       ├── auth.py          # JWT verification middleware
│   │       └── logging.py       # Structured request logging
│   ├── core/
│   │   ├── ingestion.py         # Multi-format event receiver
│   │   ├── parser.py            # Parser pipeline (syslog, CEF, JSON, WEL)
│   │   ├── correlator.py        # Threat correlation engine
│   │   └── alerting.py          # Alert dedup, triage, notification
│   ├── database/
│   │   ├── connection.py        # DuckDB connection pool
│   │   └── schema.py            # Table definitions and migrations
│   ├── models/
│   │   ├── event.py             # Pydantic event models
│   │   ├── alert.py             # Alert models
│   │   └── user.py              # User and role models
│   └── utils/
│       ├── geoip.py             # IP geolocation enrichment
│       └── threat_intel.py      # IOC feed integration
├── tests/
│   ├── conftest.py              # Fixtures and test DB setup
│   ├── test_ingestion.py        # Ingestion pipeline tests
│   ├── test_search.py           # Query engine tests
│   ├── test_alerts.py           # Alert lifecycle tests
│   └── test_correlator.py       # Correlation rule tests
├── frontend/
│   ├── index.html               # Login page
│   ├── dashboard.html           # Main dashboard
│   └── static/
│       ├── css/main.css
│       └── js/dashboard.js      # WebSocket client
├── docs/
│   └── API.md                   # Full API reference
├── scripts/
│   ├── seed_demo_data.py        # Load 10K sample events for testing
│   └── generate_load.py         # Load testing script
├── config/
│   └── correlation_rules.yaml   # Built-in detection rules
├── docker-compose.yml
├── Dockerfile
├── .env.example
├── requirements.txt
└── pyproject.toml
```

---

## API Reference

All endpoints require a `Bearer` JWT token in the `Authorization` header, except `/auth/login` and `/health`.

### Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/auth/login` | Obtain JWT access + refresh tokens |
| `POST` | `/auth/refresh` | Refresh access token |
| `GET` | `/auth/me` | Get current user info |
| `POST` | `/auth/users` | Create user (admin only) |

### Event Ingestion

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/events/ingest` | Ingest single event (JSON) |
| `POST` | `/events/ingest/batch` | Ingest batch (up to 10,000 events) |
| `POST` | `/events/ingest/syslog` | Ingest raw syslog line |
| `POST` | `/events/ingest/cef` | Ingest CEF-formatted event |
| `GET` | `/events/{event_id}` | Retrieve single event by ID |

### Search & Query

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/search` | Full-text + field search with filter/stats/sort |
| `GET` | `/search/fields` | List all indexed field names |
| `GET` | `/search/sourcetypes` | List all source types |

### Alerts

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/alerts` | List alerts with filtering and pagination |
| `GET` | `/alerts/{alert_id}` | Get alert details |
| `PATCH` | `/alerts/{alert_id}/status` | Update alert status (open/investigating/closed) |
| `GET` | `/alerts/stats` | Alert count by severity/status |

### Dashboard & Metrics

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/dashboard/summary` | Event counts, alert stats, top sources |
| `GET` | `/dashboard/timeline` | Events per hour for last 24h |
| `GET` | `/dashboard/top-sources` | Top 10 event sources |
| `WS` | `/ws/events` | WebSocket live event feed |

### System

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Health check (no auth required) |
| `GET` | `/metrics` | Ingestion rate, queue depth, storage size |

Full schema with request/response examples: [`docs/API.md`](docs/API.md)

---

## Search Query Syntax

SentinelSIEM supports a Splunk-like query syntax:

```
# Basic field search
index=firewall action=blocked

# Text search with field filter
"failed login" host=webserver01

# With time range
index=auth src_ip=192.168.1.50 | since=1h

# Aggregate statistics
index=firewall | stats count by src_ip, action | sort -count | head 20

# Sequence search (brute force detection)
index=auth action=failed | group_by src_ip | count > 5 | window=60s
```

---

## Correlation Rules

Rules are defined in `config/correlation_rules.yaml` and loaded at startup:

```yaml
rules:
  - id: RULE-001
    name: SSH Brute Force
    description: More than 5 failed SSH logins from one IP in 60 seconds
    severity: high
    mitre_attack: T1110.001
    condition:
      type: threshold
      index: auth
      filter: "action=failed AND dst_port=22"
      group_by: src_ip
      threshold: 5
      window_seconds: 60

  - id: RULE-002
    name: Privilege Escalation Attempt
    description: sudo failure followed by success from same user
    severity: critical
    mitre_attack: T1548.003
    condition:
      type: sequence
      events:
        - filter: "process=sudo AND action=failed"
          field: user
        - filter: "process=sudo AND action=success"
          same_field: user
          within_seconds: 300
```

---

## Testing

```bash
# Run full test suite
pytest tests/ -v

# Run with coverage report
pytest tests/ --cov=sentinelsiem --cov-report=term-missing

# Run specific test module
pytest tests/test_correlator.py -v

# Run load test (requires running instance)
python scripts/generate_load.py --eps 1000 --duration 60
```

Current test coverage: **64 tests passing** across ingestion, search, alert lifecycle, correlation engine, and API authentication.

---

## Configuration

All configuration is via environment variables. Copy `.env.example` to `.env`:

```env
# Application
APP_ENV=production
SECRET_KEY=your-secret-key-here-change-this
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30

# Database
DUCKDB_PATH=./data/sentinel.duckdb
DUCKDB_MEMORY_LIMIT=4GB
DUCKDB_THREADS=4

# Ingestion
MAX_BATCH_SIZE=10000
INGEST_QUEUE_SIZE=50000

# Alerting
ALERT_DEDUP_WINDOW_SECONDS=300
WEBHOOK_URL=

# Admin
ADMIN_USERNAME=admin
ADMIN_PASSWORD=SentinelAdmin@2024
```

---

## Roadmap

- [ ] Apache Kafka integration for high-throughput ingestion (1M+ eps)
- [ ] ClickHouse backend for petabyte-scale storage
- [ ] ML-based anomaly detection (Isolation Forest, LSTM)
- [ ] MISP / STIX-TAXII threat intelligence feeds
- [ ] SOAR integration (webhooks, Jira, PagerDuty)
- [ ] Multi-tenancy with index-level isolation
- [ ] SAML 2.0 / OIDC SSO (Okta, Azure AD)
- [ ] Sigma rule import support
- [ ] MITRE ATT&CK heatmap in dashboard

---

## Security Notes

- All API endpoints require JWT authentication
- Passwords are hashed with bcrypt (cost factor 12)
- DuckDB file is not exposed externally
- SQL queries use parameterized statements exclusively
- Sensitive fields (passwords, tokens) are never logged
- CORS is configurable via `ALLOWED_ORIGINS` env variable

---

## Contributing

1. Fork the repo
2. Create a feature branch: `git checkout -b feature/kafka-ingestion`
3. Add tests for your changes
4. Ensure `pytest tests/` passes
5. Submit a pull request

---

## Author

**Ayushman Raj** — Smart contract security researcher and software engineer.

- GitHub: [@ayushmann79](https://github.com/ayushmann79)
- Twitter/X: [@ayushblock](https://twitter.com/ayushblock)

---

## License

MIT License — see [LICENSE](LICENSE) for details.
