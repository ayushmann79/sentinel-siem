"""Tests for the search query engine — 20 test cases."""

import pytest


class TestSearchBasic:
    def test_search_returns_200(self, client, admin_headers):
        r = client.post("/search", json={"query": "*"}, headers=admin_headers)
        assert r.status_code == 200

    def test_search_response_schema(self, client, admin_headers):
        r = client.post("/search", json={"query": "*"}, headers=admin_headers)
        data = r.json()
        assert "total" in data
        assert "returned" in data
        assert "took_ms" in data
        assert "events" in data

    def test_search_took_ms_is_float(self, client, admin_headers):
        r = client.post("/search", json={"query": "*"}, headers=admin_headers)
        assert isinstance(r.json()["took_ms"], (int, float))

    def test_search_by_index(self, client, admin_headers, sample_event_payload):
        client.post("/events/ingest", json=sample_event_payload, headers=admin_headers)
        r = client.post("/search", json={"query": "*", "index": "auth"}, headers=admin_headers)
        assert r.status_code == 200
        for ev in r.json()["events"]:
            assert ev["index"] == "auth"

    def test_search_by_host(self, client, admin_headers, sample_event_payload):
        r = client.post(
            "/search",
            json={"query": "*", "host": "webserver01", "since": "1h"},
            headers=admin_headers,
        )
        assert r.status_code == 200

    def test_search_limit_respected(self, client, admin_headers):
        r = client.post("/search", json={"query": "*", "limit": 5}, headers=admin_headers)
        assert len(r.json()["events"]) <= 5

    def test_search_requires_auth(self, client):
        r = client.post("/search", json={"query": "*"})
        assert r.status_code == 403

    def test_search_invalid_sort_field(self, client, admin_headers):
        r = client.post(
            "/search", json={"query": "*", "sort_by": "DROP TABLE"}, headers=admin_headers
        )
        assert r.status_code == 422

    def test_search_invalid_sort_dir(self, client, admin_headers):
        r = client.post(
            "/search", json={"query": "*", "sort_dir": "INJECTION"}, headers=admin_headers
        )
        assert r.status_code == 422

    def test_search_invalid_time_spec(self, client, admin_headers):
        r = client.post(
            "/search", json={"query": "*", "since": "badspec"}, headers=admin_headers
        )
        assert r.status_code == 422


class TestSearchFilters:
    def test_kv_filter_in_query_string(self, client, admin_headers, sample_cef_payload):
        client.post("/events/ingest", json=sample_cef_payload, headers=admin_headers)
        r = client.post(
            "/search",
            json={"query": "sourcetype=cef", "since": "1h"},
            headers=admin_headers,
        )
        assert r.status_code == 200

    def test_text_search_in_raw(self, client, admin_headers, sample_event_payload):
        client.post("/events/ingest", json=sample_event_payload, headers=admin_headers)
        r = client.post(
            "/search",
            json={"query": "Failed password", "since": "1h"},
            headers=admin_headers,
        )
        assert r.status_code == 200

    def test_search_offset_pagination(self, client, admin_headers):
        r1 = client.post("/search", json={"query": "*", "limit": 5, "offset": 0}, headers=admin_headers)
        r2 = client.post("/search", json={"query": "*", "limit": 5, "offset": 5}, headers=admin_headers)
        assert r1.status_code == 200
        assert r2.status_code == 200


class TestSearchMeta:
    def test_list_fields(self, client, admin_headers):
        r = client.get("/search/fields", headers=admin_headers)
        assert r.status_code == 200
        assert "fields" in r.json()
        assert "src_ip" in r.json()["fields"]

    def test_list_sourcetypes(self, client, admin_headers):
        r = client.get("/search/sourcetypes", headers=admin_headers)
        assert r.status_code == 200
        assert "sourcetypes" in r.json()

    def test_sourcetypes_has_name_and_count(self, client, admin_headers):
        r = client.get("/search/sourcetypes", headers=admin_headers)
        for item in r.json()["sourcetypes"]:
            assert "name" in item
            assert "count" in item


class TestAlerts:
    def test_list_alerts_returns_200(self, client, admin_headers):
        r = client.get("/alerts", headers=admin_headers)
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_alert_stats_schema(self, client, admin_headers):
        r = client.get("/alerts/stats", headers=admin_headers)
        assert r.status_code == 200
        data = r.json()
        assert "total" in data
        assert "by_severity" in data
        assert "by_status" in data
        assert "last_24h" in data

    def test_get_nonexistent_alert(self, client, admin_headers):
        r = client.get("/alerts/does-not-exist", headers=admin_headers)
        assert r.status_code == 404

    def test_filter_alerts_by_status(self, client, admin_headers):
        r = client.get("/alerts?status=open", headers=admin_headers)
        assert r.status_code == 200
        for alert in r.json():
            assert alert["status"] == "open"
