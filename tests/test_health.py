"""Tests for application factory, health probes, readiness checks, and dashboard."""

from unittest.mock import patch

from flask import Flask
from sqlalchemy.exc import OperationalError

from app import create_app


def test_app_factory_creates_app():
    """Verify the application factory instantiates a valid Flask app with test configuration."""
    app = create_app("testing")
    assert isinstance(app, Flask)
    assert app.config["TESTING"] is True
    assert app.config["DEBUG"] is False


def test_health_endpoint_returns_minimal_ok(client):
    """Verify GET /health returns HTTP 200 with minimal status JSON and no infrastructure leaks."""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.is_json
    data = response.get_json()
    assert data == {"status": "ok"}
    # Verify sensitive environment/infrastructure details are not disclosed
    assert "version" not in data
    assert "database" not in data
    assert "config" not in data
    assert "host" not in data


def test_readiness_endpoint_success_when_db_available(client):
    """Verify GET /ready returns HTTP 200 when database connectivity is healthy."""
    response = client.get("/ready")
    assert response.status_code == 200
    assert response.is_json
    data = response.get_json()
    assert data == {"status": "ready"}
    # Verify no internal connection strings or topology details leaked
    assert "database_uri" not in data


def test_readiness_endpoint_fails_safely_when_db_unavailable(client):
    """Verify GET /ready returns HTTP 503 and minimal status when database connectivity fails."""
    with patch(
        "app.routes.health.db.session.execute",
        side_effect=OperationalError("connection refused", {}, None),
    ):
        response = client.get("/ready")
        assert response.status_code == 503
        assert response.is_json
        data = response.get_json()
        assert data == {"status": "unavailable"}
        # Must not disclose raw exception details or database stack traces
        assert "connection refused" not in response.get_data(as_text=True)


def test_dashboard_route_renders_identity(client):
    """Verify root GET / renders project identity, educational mission, and security notices."""
    response = client.get("/")
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "Vulnerability Assessment and Defense Lab" in html
    assert "Phase 1" in html
    assert "Security &amp; Isolation Boundary" in html
