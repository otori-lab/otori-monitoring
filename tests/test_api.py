"""
Tests pour l'API Otori Monitoring.
"""

import pytest
from fastapi.testclient import TestClient


class TestHealthEndpoint:
    """Tests pour le endpoint /health."""

    def test_health_returns_200(self, client: TestClient):
        """Le health check doit retourner 200."""
        response = client.get("/health")
        assert response.status_code == 200

    def test_health_returns_correct_structure(self, client: TestClient):
        """Le health check doit retourner la bonne structure."""
        response = client.get("/health")
        data = response.json()

        assert "status" in data
        assert "version" in data
        assert "environment" in data
        assert "database" in data

    def test_health_status_is_healthy(self, client: TestClient):
        """Le status doit être 'healthy'."""
        response = client.get("/health")
        data = response.json()

        assert data["status"] == "healthy"


class TestIngestEndpoint:
    """Tests pour le endpoint /ingest."""

    def test_ingest_accepts_valid_event(self, client: TestClient, sample_event: dict):
        """L'ingestion doit accepter un événement valide."""
        response = client.post("/ingest", json=sample_event)
        assert response.status_code == 200
        assert response.json() == {"ok": True}

    def test_ingest_rejects_missing_required_fields(self, client: TestClient):
        """L'ingestion doit rejeter un événement sans champs requis."""
        response = client.post("/ingest", json={})
        assert response.status_code == 422

    def test_ingest_stores_event(self, client: TestClient, sample_event: dict):
        """L'événement doit être stocké en base."""
        client.post("/ingest", json=sample_event)

        # Vérifier via KPI
        response = client.get("/kpi")
        data = response.json()

        assert data["total_sessions"] >= 1


class TestKpiEndpoint:
    """Tests pour le endpoint /kpi."""

    def test_kpi_returns_200(self, client: TestClient):
        """Le endpoint KPI doit retourner 200."""
        response = client.get("/kpi")
        assert response.status_code == 200

    def test_kpi_returns_correct_structure(self, client: TestClient):
        """Les KPIs doivent avoir la bonne structure."""
        response = client.get("/kpi")
        data = response.json()

        expected_keys = [
            "total_sessions",
            "unique_ips",
            "avg_duration_sec",
            "total_commands",
            "cmds_per_session",
            "login_success",
            "login_failed",
        ]

        for key in expected_keys:
            assert key in data

    def test_kpi_accepts_hours_parameter(self, client: TestClient):
        """Le paramètre hours doit être accepté."""
        response = client.get("/kpi?hours=48")
        assert response.status_code == 200


class TestRecentSessionsEndpoint:
    """Tests pour le endpoint /sessions/recent."""

    def test_recent_returns_200(self, client: TestClient):
        """Le endpoint doit retourner 200."""
        response = client.get("/sessions/recent")
        assert response.status_code == 200

    def test_recent_returns_list(self, client: TestClient):
        """Le endpoint doit retourner une liste."""
        response = client.get("/sessions/recent")
        data = response.json()

        assert isinstance(data, list)

    def test_recent_accepts_limit_parameter(self, client: TestClient):
        """Le paramètre limit doit être accepté."""
        response = client.get("/sessions/recent?limit=5")
        assert response.status_code == 200


class TestDashboardPage:
    """Tests pour la page dashboard."""

    def test_dashboard_returns_200(self, client: TestClient):
        """La page dashboard doit retourner 200."""
        response = client.get("/")
        assert response.status_code == 200

    def test_dashboard_returns_html(self, client: TestClient):
        """La page dashboard doit retourner du HTML."""
        response = client.get("/")
        assert "text/html" in response.headers["content-type"]
