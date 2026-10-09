"""DuckDB schema definitions and migration runner."""

SCHEMA_VERSION = 4

CREATE_STATEMENTS = [
    # ── Schema version tracking ──────────────────────────────────────────
    """
    CREATE TABLE IF NOT EXISTS schema_version (
        version     INTEGER PRIMARY KEY,
        applied_at  TIMESTAMP DEFAULT current_timestamp
    )
    """,

    # ── Core events table ────────────────────────────────────────────────
    """
    CREATE TABLE IF NOT EXISTS events (
        id              VARCHAR PRIMARY KEY,
        ts              TIMESTAMP NOT NULL,
        ingest_ts       TIMESTAMP DEFAULT current_timestamp,

        -- Routing
        index           VARCHAR NOT NULL DEFAULT 'main',
        sourcetype      VARCHAR NOT NULL DEFAULT 'generic',
        source          VARCHAR,
        host            VARCHAR,

        -- Raw & normalized
        raw             VARCHAR NOT NULL,
        message         VARCHAR,

        -- Network (ECS-aligned)
        src_ip          VARCHAR,
        dst_ip          VARCHAR,
        src_port        INTEGER,
        dst_port        INTEGER,
        protocol        VARCHAR,
        network_bytes   BIGINT,

        -- Identity
        username        VARCHAR,
        process         VARCHAR,
        pid             INTEGER,

        -- Outcome
        action          VARCHAR,
        outcome         VARCHAR,
        severity        INTEGER DEFAULT 0,

        -- Dynamic fields (key-value pairs from parser)
        fields          JSON,

        -- Geo enrichment
        src_country     VARCHAR,
        src_city        VARCHAR,
        src_asn         VARCHAR,

        -- Threat intel
        is_ioc          BOOLEAN DEFAULT false,
        ioc_type        VARCHAR
    )
    """,

    # ── Alerts table ─────────────────────────────────────────────────────
    """
    CREATE TABLE IF NOT EXISTS alerts (
        id              VARCHAR PRIMARY KEY,
        created_at      TIMESTAMP DEFAULT current_timestamp,
        updated_at      TIMESTAMP DEFAULT current_timestamp,

        rule_id         VARCHAR NOT NULL,
        rule_name       VARCHAR NOT NULL,
        severity        VARCHAR NOT NULL,    -- critical / high / medium / low / info
        status          VARCHAR DEFAULT 'open',  -- open / investigating / closed / false_positive

        -- MITRE ATT&CK
        mitre_tactic    VARCHAR,
        mitre_technique VARCHAR,

        -- Context
        description     VARCHAR,
        src_ip          VARCHAR,
        username        VARCHAR,
        host            VARCHAR,
        event_count     INTEGER DEFAULT 1,
        first_seen      TIMESTAMP,
        last_seen       TIMESTAMP,

        -- Dedup key prevents duplicate alerts in window
        dedup_key       VARCHAR,

        -- Linked events
        event_ids       JSON,

        -- Analyst notes
        analyst         VARCHAR,
        notes           VARCHAR
    )
    """,

    # ── Users table ──────────────────────────────────────────────────────
    """
    CREATE TABLE IF NOT EXISTS users (
        id              VARCHAR PRIMARY KEY,
        created_at      TIMESTAMP DEFAULT current_timestamp,
        username        VARCHAR UNIQUE NOT NULL,
        email           VARCHAR UNIQUE NOT NULL,
        password_hash   VARCHAR NOT NULL,
        role            VARCHAR DEFAULT 'analyst',   -- admin / analyst / readonly
        is_active       BOOLEAN DEFAULT true,
        last_login      TIMESTAMP
    )
    """,

    # ── Correlation state (for sequence / threshold rules) ───────────────
    """
    CREATE TABLE IF NOT EXISTS correlation_state (
        key             VARCHAR PRIMARY KEY,
        rule_id         VARCHAR NOT NULL,
        data            JSON NOT NULL,
        expires_at      TIMESTAMP NOT NULL
    )
    """,

    # ── Audit log ────────────────────────────────────────────────────────
    """
    CREATE TABLE IF NOT EXISTS audit_log (
        id              VARCHAR PRIMARY KEY,
        ts              TIMESTAMP DEFAULT current_timestamp,
        username        VARCHAR,
        action          VARCHAR NOT NULL,
        resource        VARCHAR,
        resource_id     VARCHAR,
        ip_address      VARCHAR,
        details         JSON
    )
    """,

    # ── Indexes ──────────────────────────────────────────────────────────
    "CREATE INDEX IF NOT EXISTS idx_events_ts         ON events(ts)",
    "CREATE INDEX IF NOT EXISTS idx_events_index      ON events(index)",
    "CREATE INDEX IF NOT EXISTS idx_events_host       ON events(host)",
    "CREATE INDEX IF NOT EXISTS idx_events_src_ip     ON events(src_ip)",
    "CREATE INDEX IF NOT EXISTS idx_events_username   ON events(username)",
    "CREATE INDEX IF NOT EXISTS idx_alerts_status     ON alerts(status)",
    "CREATE INDEX IF NOT EXISTS idx_alerts_severity   ON alerts(severity)",
    "CREATE INDEX IF NOT EXISTS idx_alerts_dedup      ON alerts(dedup_key)",
]
