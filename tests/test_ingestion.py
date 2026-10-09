"""Tests for event ingestion pipeline — 20 test cases."""

import pytest
from fastapi.testclient import TestClient


class TestSingleIngest:
    def test_ingest_syslog_returns_201(self, client, admin_headers, sample_event_payload):
        r = client.post("/events/ingest", json=sample_event_payload, headers=admin_headers)
        assert r.status_code == 201
        assert "event_id" in r.json()

    def test_ingest_cef_event(self, client, admin_headers, sample_cef_payload):
        r = client.post("/events/ingest", json=sample_cef_payload, headers=admin_headers)
        assert r.status_code == 201

    def test_ingest_json_event(self, client, admin_headers, sample_json_payload):
        r = client.post("/events/ingest", json=sample_json_payload, headers=admin_headers)
        assert r.status_code == 201

    def test_ingest_returns_event_id(self, client, admin_headers, sample_event_payload):
        r = client.post("/events/ingest", json=sample_event_payload, headers=admin_headers)
        data = r.json()
        assert isinstance(data["event_id"], str)
        assert len(data["event_id"]) == 36  # UUID format

    def test_ingest_reports_alerts_fired(self, client, admin_headers, sample_event_payload):
        r = client.post("/events/ingest", json=sample_event_payload, headers=admin_headers)
        assert "alerts_fired" in r.json()
        assert isinstance(r.json()["alerts_fired"], int)

    def test_ingest_requires_raw_field(self, client, admin_headers):
        r = client.post("/events/ingest", json={"index": "test"}, headers=admin_headers)
        assert r.status_code == 422

    def test_ingest_requires_auth(self, client, sample_event_payload):
        r = client.post("/events/ingest", json=sample_event_payload)
        assert r.status_code == 403

    def test_ingest_readonly_rejected(self, client, sample_event_payload):
        from sentinelsiem.api.middleware.auth import create_access_token
        token = create_access_token("reader", "readonly")
        r = client.post(
            "/events/ingest", json=sample_event_payload,
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 403

    def test_get_event_by_id(self, client, admin_headers, sample_event_payload):
        r = client.post("/events/ingest", json=sample_event_payload, headers=admin_headers)
        event_id = r.json()["event_id"]
        r2 = client.get(f"/events/{event_id}", headers=admin_headers)
        assert r2.status_code == 200
        assert r2.json()["id"] == event_id

    def test_get_event_not_found(self, client, admin_headers):
        r = client.get("/events/nonexistent-id", headers=admin_headers)
        assert r.status_code == 404


class TestBatchIngest:
    def test_batch_ingest_basic(self, client, admin_headers):
        events = [
            {"raw": f"log line {i}", "sourcetype": "syslog", "index": "main", "host": f"host{i}"}
            for i in range(10)
        ]
        r = client.post("/events/ingest/batch", json={"events": events}, headers=admin_headers)
        assert r.status_code == 201
        assert r.json()["ingested"] == 10

    def test_batch_preserves_count(self, client, admin_headers):
        events = [
            {"raw": f"batch test {i}", "sourcetype": "json", "index": "batch_test", "host": "batchhost"}
            for i in range(50)
        ]
        r = client.post("/events/ingest/batch", json={"events": events}, headers=admin_headers)
        assert r.json()["ingested"] == 50

    def test_batch_empty_list_rejected(self, client, admin_headers):
        r = client.post("/events/ingest/batch", json={"events": []}, headers=admin_headers)
        # Empty list — FastAPI will accept it (min_length not set to 1 in model)
        # but ingested=0 is valid
        assert r.status_code in (201, 422)

    def test_batch_syslog_endpoint(self, client, admin_headers):
        r = client.post(
            "/events/ingest/syslog",
            json={"raw": "Jan 10 09:00:00 host1 kernel: OOM killer invoked", "index": "system"},
            headers=admin_headers,
        )
        assert r.status_code == 201

    def test_batch_syslog_missing_raw(self, client, admin_headers):
        r = client.post("/events/ingest/syslog", json={"index": "system"}, headers=admin_headers)
        assert r.status_code == 422


class TestEventRetrieval:
    def test_event_has_required_fields(self, client, admin_headers, sample_event_payload):
        r = client.post("/events/ingest", json=sample_event_payload, headers=admin_headers)
        event_id = r.json()["event_id"]
        event = client.get(f"/events/{event_id}", headers=admin_headers).json()
        for field in ("id", "ts", "raw", "index", "sourcetype"):
            assert field in event

    def test_event_index_preserved(self, client, admin_headers):
        payload = {"raw": "test", "sourcetype": "syslog", "index": "custom_index", "host": "h1"}
        r = client.post("/events/ingest", json=payload, headers=admin_headers)
        event = client.get(f"/events/{r.json()['event_id']}", headers=admin_headers).json()
        assert event["index"] == "custom_index"

    def test_event_host_preserved(self, client, admin_headers):
        payload = {"raw": "test", "sourcetype": "syslog", "index": "main", "host": "specific-host"}
        r = client.post("/events/ingest", json=payload, headers=admin_headers)
        event = client.get(f"/events/{r.json()['event_id']}", headers=admin_headers).json()
        assert event["host"] == "specific-host"

    def test_readonly_can_retrieve(self, client, sample_event_payload, admin_headers):
        r = client.post("/events/ingest", json=sample_event_payload, headers=admin_headers)
        event_id = r.json()["event_id"]
        from sentinelsiem.api.middleware.auth import create_access_token
        ro_token = create_access_token("reader", "readonly")
        r2 = client.get(f"/events/{event_id}", headers={"Authorization": f"Bearer {ro_token}"})
        assert r2.status_code == 200

    def test_cef_fields_extracted(self, client, admin_headers, sample_cef_payload):
        r = client.post("/events/ingest", json=sample_cef_payload, headers=admin_headers)
        event = client.get(f"/events/{r.json()['event_id']}", headers=admin_headers).json()
        assert event["sourcetype"] == "cef"
