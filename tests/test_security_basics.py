"""Security baseline and configuration isolation tests for VADL."""

import logging
import socket
from unittest.mock import patch

import pytest

from app import create_app
from app.config import DevelopmentConfig, TestingConfig, get_config
from app.logging_config import RedactingFormatter


def test_unknown_routes_return_404(client):
    """Verify unknown routes return HTTP 404 safely for both HTML and JSON requests."""
    # HTML response
    response = client.get("/non-existent-lab-endpoint")
    assert response.status_code == 404
    assert "Resource Not Found" in response.get_data(as_text=True)

    # JSON response
    response_json = client.get("/health/non-existent", headers={"Accept": "application/json"})
    assert response_json.status_code == 404
    assert response_json.is_json
    assert response_json.get_json() == {"error": "Resource not found"}


def test_unexpected_server_errors_return_generic_500_without_tracebacks():
    """Verify unexpected server errors return a generic 500 response without exposing stack traces."""
    app = create_app("testing")

    # Define a test endpoint that raises an unhandled runtime error
    @app.route("/test-trigger-500")
    def trigger_error():
        raise RuntimeError("Simulated internal database crash or secret decryption failure")

    test_client = app.test_client()

    # Request HTML 500 page
    response = test_client.get("/test-trigger-500")
    assert response.status_code == 500
    html = response.get_data(as_text=True)
    assert "Internal Server Error" in html
    # Ensure raw exception message and stack trace are NOT exposed to the client
    assert "Simulated internal database crash" not in html
    assert "Traceback" not in html

    # Request JSON 500 response
    response_json = test_client.get(
        "/test-trigger-500", headers={"Content-Type": "application/json"}
    )
    assert response_json.status_code == 500
    assert response_json.is_json
    data = response_json.get_json()
    assert data == {"error": "An internal server error occurred"}
    assert "Simulated internal database crash" not in str(data)


def test_testing_config_does_not_use_development_database():
    """Verify testing configuration uses an isolated in-memory database and never touches dev DB."""
    test_cfg = TestingConfig()
    dev_cfg = DevelopmentConfig()

    assert test_cfg.SQLALCHEMY_DATABASE_URI == "sqlite:///:memory:"
    assert test_cfg.SQLALCHEMY_DATABASE_URI != dev_cfg.SQLALCHEMY_DATABASE_URI
    assert "vadl_dev.db" not in test_cfg.SQLALCHEMY_DATABASE_URI


def test_production_config_does_not_enable_debug_mode(monkeypatch):
    """Verify production configuration strictly disables Flask debug mode."""
    # Provide a valid production secret key to pass validation
    monkeypatch.setenv("SECRET_KEY", "a" * 32)
    monkeypatch.setenv("FLASK_CONFIG", "production")

    prod_cfg = get_config("production")
    assert prod_cfg.DEBUG is False
    assert prod_cfg.TESTING is False

    prod_app = create_app("production")
    assert prod_app.config["DEBUG"] is False


def test_missing_or_weak_production_secrets_fail_safely(monkeypatch):
    """Verify the application safely refuses to boot in production when SECRET_KEY is missing or insecure."""
    # Test case 1: Insecure default key
    monkeypatch.setenv("SECRET_KEY", "vadl-default-insecure-dev-key")
    with pytest.raises(ValueError, match="CRITICAL SECURITY FAILURE"):
        get_config("production")

    # Test case 2: Key too short (< 32 chars)
    monkeypatch.setenv("SECRET_KEY", "too-short-secret")
    with pytest.raises(ValueError, match="CRITICAL SECURITY FAILURE"):
        get_config("production")

    # Test case 3: Empty string
    monkeypatch.setenv("SECRET_KEY", "")
    with pytest.raises(ValueError, match="CRITICAL SECURITY FAILURE"):
        get_config("production")


def test_startup_does_not_require_external_network_services():
    """Verify application creation and teardown do not invoke any external network sockets."""

    def guard_socket(*args, **kwargs):
        raise AssertionError("Unexpected external network socket creation during offline startup!")

    with patch.object(socket, "socket", side_effect=guard_socket):
        # Initializing app in testing mode must be 100% offline and deterministic
        app = create_app("testing")
        assert app is not None


def test_security_response_headers_are_present(client):
    """Verify baseline HTTP security headers are attached to responses."""
    response = client.get("/")
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert response.headers.get("X-Frame-Options") == "DENY"
    assert response.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
    assert "Content-Security-Policy" in response.headers


def test_payload_size_limit_rejection():
    """Verify request payload size ceiling rejects payloads that exceed MAX_CONTENT_LENGTH."""
    test_app = create_app("testing")

    @test_app.route("/test-upload", methods=["POST"])
    def upload_endpoint():
        from flask import request

        _ = request.data
        return {"status": "ok"}, 200

    test_client = test_app.test_client()
    # MAX_CONTENT_LENGTH is 1MB (1048576 bytes); send payload exceeding this ceiling
    oversized_data = b"X" * (1024 * 1024 + 1024)
    response = test_client.post(
        "/test-upload",
        data=oversized_data,
        content_type="application/octet-stream",
    )
    assert response.status_code == 413


def test_redacting_logger_scrubs_sensitive_data():
    """Verify log formatter redacts passwords, tokens, cookies, and bearer authorization."""
    formatter = RedactingFormatter(fmt="%(message)s")
    record = logging.LogRecord(
        name="test_logger",
        level=logging.INFO,
        pathname="",
        lineno=0,
        msg="User auth failed: password='supersecretpass123', token=eyJh123456, Authorization: Bearer secrettoken999, Cookie: session=abcdef123456",
        args=(),
        exc_info=None,
    )
    formatted = formatter.format(record)

    assert "supersecretpass123" not in formatted
    assert "eyJh123456" not in formatted
    assert "secrettoken999" not in formatted
    assert "abcdef123456" not in formatted
    assert "[REDACTED]" in formatted
