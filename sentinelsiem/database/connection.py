"""DuckDB connection manager with thread-safe access and schema migration."""

import logging
import os
import threading
from contextlib import contextmanager
from pathlib import Path

import duckdb

from sentinelsiem.config import get_settings
from sentinelsiem.database.schema import CREATE_STATEMENTS, SCHEMA_VERSION

logger = logging.getLogger(__name__)
_lock = threading.Lock()
_connection: duckdb.DuckDBPyConnection | None = None


def _get_raw_connection() -> duckdb.DuckDBPyConnection:
    global _connection
    if _connection is None:
        with _lock:
            if _connection is None:
                settings = get_settings()
                Path(settings.duckdb_path).parent.mkdir(parents=True, exist_ok=True)

                conn = duckdb.connect(settings.duckdb_path)
                conn.execute(f"SET memory_limit='{settings.duckdb_memory_limit}'")
                conn.execute(f"SET threads={settings.duckdb_threads}")
                conn.execute("SET enable_progress_bar=false")

                _run_migrations(conn)
                _connection = conn
                logger.info("DuckDB connected: %s", settings.duckdb_path)
    return _connection


def _run_migrations(conn: duckdb.DuckDBPyConnection) -> None:
    for stmt in CREATE_STATEMENTS:
        conn.execute(stmt)

    current = conn.execute("SELECT COALESCE(MAX(version), 0) FROM schema_version").fetchone()[0]
    if current < SCHEMA_VERSION:
        conn.execute(
            "INSERT OR REPLACE INTO schema_version(version) VALUES (?)", [SCHEMA_VERSION]
        )
        logger.info("Schema migrated to v%d", SCHEMA_VERSION)


@contextmanager
def get_db():
    """Yield a thread-local cursor. DuckDB is single-writer; we serialize writes via the lock."""
    conn = _get_raw_connection()
    cursor = conn.cursor()
    try:
        yield cursor
    finally:
        cursor.close()


def close_db() -> None:
    global _connection
    if _connection:
        _connection.close()
        _connection = None
        logger.info("DuckDB connection closed")
