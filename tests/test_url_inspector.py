"""Tests for Live URL Security Inspector and Header Analyzer."""

from unittest.mock import MagicMock, patch

from requests.exceptions import ConnectionError

from app.scanner.url_inspector import inspect_url


def test_inspect_url_connection_failure():
    """Verify endpoint connection failure is gracefully handled and recorded as CRITICAL finding."""
    with patch("requests.Session.get", side_effect=ConnectionError("Failed to resolve host")):
        result = inspect_url("http://nonexistent-domain-test.local")
        assert result["status_code"] == 0
        assert len(result["findings"]) == 1
        f = result["findings"][0]
        assert f["title"] == "Endpoint Connection Failure"
        assert f["severity"] == "CRITICAL"
        assert result["grade_result"]["grade"] == "B" or result["grade_result"]["grade"] in (
            "B",
            "C",
        )
        assert result["grade_result"]["score"] == 80  # 100 - 20 = 80


def test_inspect_url_identifies_missing_headers_and_cookies():
    """Verify passive inspection flags missing CSP, HSTS, XFO, XCTO, and insecure cookies."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.elapsed.total_seconds.return_value = 0.045
    # Plain response missing all security headers
    mock_resp.headers = {
        "Server": "Apache/2.4.41 (Ubuntu)",
        "X-Powered-By": "PHP/7.4.3",
        "Content-Type": "text/html; charset=UTF-8",
    }

    # Insecure cookie missing HttpOnly and Secure
    mock_cookie = MagicMock()
    mock_cookie.name = "session_id"
    mock_cookie.secure = False
    mock_cookie.has_nonstandard_attr.return_value = False
    mock_cookie._rest = {}
    mock_resp.cookies = [mock_cookie]

    with patch("requests.Session.get", return_value=mock_resp):
        result = inspect_url("https://insecure-app.example.com")
        assert result["status_code"] == 200
        assert result["response_time_ms"] == 45.0

        finding_titles = [f["title"] for f in result["findings"]]
        assert "Missing HTTP Strict Transport Security (HSTS)" in finding_titles
        assert "Missing Content-Security-Policy (CSP)" in finding_titles
        assert "Missing or Misconfigured X-Content-Type-Options" in finding_titles
        assert "Missing Clickjacking Defense (X-Frame-Options / frame-ancestors)" in finding_titles
        assert "Server Banner Information Disclosure" in finding_titles
        assert "Technology Stack Disclosure via X-Powered-By" in finding_titles
        assert "Cookie 'session_id' Missing HttpOnly Flag" in finding_titles
        assert "Cookie 'session_id' Missing Secure Flag" in finding_titles

        # Substantial deductions should lower grade
        assert result["grade_result"]["score"] < 70
        assert result["grade_result"]["grade"] in ("D", "F")


def test_inspect_url_hardened_site_receives_high_grade():
    """Verify a properly configured hardened site achieves Grade A."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.elapsed.total_seconds.return_value = 0.030
    mock_resp.headers = {
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
        "Content-Security-Policy": "default-src 'self'; script-src 'self'; object-src 'none'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "camera=(), microphone=()",
        "Server": "CloudFront",  # Generic banner without version leak
    }
    mock_resp.cookies = []

    with patch("requests.Session.get", return_value=mock_resp):
        result = inspect_url("https://hardened.example.com")
        assert result["status_code"] == 200
        assert len(result["findings"]) == 0
        assert result["grade_result"]["score"] == 100
        assert result["grade_result"]["grade"] == "A+"
