"""Shared pytest fixtures — in-memory DuckDB, test client, sample events."""

import os
import uuid
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

# Point to in-memory DB before importing any app modules
os.environ["DUCKDB_PATH"] = ":memory:"
os.environ["SECRET_KEY"]  = "test-secret-key-not-for-production"
os.environ["ADMIN_PASSWORD"] = "TestAdmin@123"

from sentinelsiem.main import app
from sentinelsiem.database.connection import get_db
from sentinelsiem.api.middleware.auth import create_access_token


@pytest.fixture(scope="session")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="session")
def admin_token():
    return create_access_token("admin", "admin")


@pytest.fixture(scope="session")
def analyst_token():
    return create_access_token("testanalyst", "analyst")


@pytest.fixture(scope="session")
def admin_headers(admin_token):
    return {"Authorization": f"Bearer {admin_token}"}


@pytest.fixture(scope="session")
def analyst_headers(analyst_token):
    return {"Authorization": f"Bearer {analyst_token}"}


@pytest.fixture
def sample_event_payload():
    return {
        "raw": "Jan 10 08:15:32 webserver01 sshd[1234]: Failed password for root from 192.168.1.50 port 22",
        "index": "auth",
        "sourcetype": "syslog",
        "host": "webserver01",
    }


@pytest.fixture
def sample_cef_payload():
    return {
        "raw": "CEF:0|Cisco|ASA|9.8|106001|Inbound TCP connection denied|3|src=10.0.0.5 dst=172.16.0.1 spt=4444 dpt=443 act=blocked",
        "index": "firewall",
        "sourcetype": "cef",
        "host": "asa-firewall",
    }


@pytest.fixture
def sample_json_payload():
    return {
        "raw": '{"ts":"2024-01-10T08:15:32Z","event":"login","user":"alice","src_ip":"10.0.1.5","outcome":"success"}',
        "index": "auth",
        "sourcetype": "json",
        "host": "app-server",
    }
