"""Tests for authentication and dashboard endpoints — 24 test cases."""

import pytest


class TestHealth:
    def test_health_no_auth_required(self, client):
        r = client.get("/health")
        assert r.status_code == 200

    def test_health_returns_version(self, client):
        data = client.get("/health").json()
        assert "version" in data
        assert "status" in data
        assert data["status"] == "ok"

    def test_metrics_returns_counts(self, client, admin_headers):
        r = client.get("/metrics", headers=admin_headers)
        assert r.status_code == 200
        data = r.json()
        assert "events_total" in data
        assert "alerts_total" in data


class TestAuth:
    def test_login_success(self, client):
        r = client.post("/auth/login", json={"username": "admin", "password": "TestAdmin@123"})
        assert r.status_code == 200
        data = r.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"

    def test_login_wrong_password(self, client):
        r = client.post("/auth/login", json={"username": "admin", "password": "wrongpassword"})
        assert r.status_code == 401

    def test_login_wrong_username(self, client):
        r = client.post("/auth/login", json={"username": "nobody", "password": "anything"})
        assert r.status_code == 401

    def test_me_returns_user(self, client, admin_headers):
        r = client.get("/auth/me", headers=admin_headers)
        assert r.status_code == 200
        data = r.json()
        assert data["username"] == "admin"
        assert data["role"] == "admin"

    def test_me_requires_auth(self, client):
        r = client.get("/auth/me")
        assert r.status_code == 403

    def test_create_user_as_admin(self, client, admin_headers):
        r = client.post(
            "/auth/users",
            json={
                "username": "newanalyst",
                "email": "newanalyst@example.com",
                "password": "Secure@Pass1",
                "role": "analyst",
            },
            headers=admin_headers,
        )
        assert r.status_code == 200
        data = r.json()
        assert data["username"] == "newanalyst"
        assert data["role"] == "analyst"

    def test_create_user_requires_admin(self, client, analyst_headers):
        r = client.post(
            "/auth/users",
            json={"username": "hacker", "email": "h@x.com", "password": "Pass@1234", "role": "analyst"},
            headers=analyst_headers,
        )
        assert r.status_code == 403

    def test_duplicate_user_rejected(self, client, admin_headers):
        payload = {"username": "dupuser", "email": "dup@example.com", "password": "Pass@1234", "role": "analyst"}
        client.post("/auth/users", json=payload, headers=admin_headers)
        r = client.post("/auth/users", json=payload, headers=admin_headers)
        assert r.status_code == 409

    def test_invalid_token_rejected(self, client):
        r = client.get("/auth/me", headers={"Authorization": "Bearer totallyinvalidtoken"})
        assert r.status_code == 401


class TestDashboard:
    def test_summary_returns_200(self, client, admin_headers):
        r = client.get("/dashboard/summary", headers=admin_headers)
        assert r.status_code == 200

    def test_summary_schema(self, client, admin_headers):
        data = client.get("/dashboard/summary", headers=admin_headers).json()
        assert "events" in data
        assert "alerts" in data
        assert "sources" in data
        assert "total" in data["events"]
        assert "last_24h" in data["events"]

    def test_timeline_returns_200(self, client, admin_headers):
        r = client.get("/dashboard/timeline", headers=admin_headers)
        assert r.status_code == 200
        assert "timeline" in r.json()

    def test_top_sources_returns_200(self, client, admin_headers):
        r = client.get("/dashboard/top-sources", headers=admin_headers)
        assert r.status_code == 200
        assert "sources" in r.json()

    def test_dashboard_requires_auth(self, client):
        r = client.get("/dashboard/summary")
        assert r.status_code == 403
