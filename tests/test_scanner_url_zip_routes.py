"""Tests for URL and ZIP scanner routes, grading persistence, and JSON API."""

import io
import zipfile
from unittest.mock import MagicMock, patch

from app.models.scanner import SecurityScan
from app.models.user import Role


def _make_zip(files: dict[str, str]) -> io.BytesIO:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, text in files.items():
            zf.writestr(name, text)
    buf.seek(0)
    return buf


def test_scan_url_route_authenticated(client, auth):
    """Verify POST /scans/url audits target URL and stores score and grade."""
    auth.create_user(
        email="analyst_url@vadl.local",
        password="Password123!@",
        role=Role.SECURITY_ANALYST,
    )
    auth.login(email="analyst_url@vadl.local", password="Password123!@")
    token = auth.get_csrf_token("/scans")

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.elapsed.total_seconds.return_value = 0.05
    mock_resp.headers = {
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "default-src 'self'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "camera=()",
    }
    mock_resp.cookies = []

    with patch("requests.Session.get", return_value=mock_resp):
        resp = client.post(
            "/scans/url",
            data={
                "csrf_token": token,
                "target_url": "https://secure-target.local",
            },
            follow_redirects=True,
        )
        assert resp.status_code == 200
        html = resp.get_data(as_text=True)
        assert "GRADE" in html

        scan = SecurityScan.query.filter_by(scanner_type="URL_INSPECTOR").first()
        assert scan is not None
        assert scan.scan_mode == "URL"
        assert scan.target_url == "https://secure-target.local"
        assert scan.score >= 90
        assert scan.grade in ("A+", "A")


def test_scan_url_json_api(client, auth):
    """Verify POST /scans/url returns JSON when requested."""
    auth.create_user(
        email="analyst_url_json@vadl.local",
        password="Password123!@",
        role=Role.SECURITY_ANALYST,
    )
    auth.login(email="analyst_url_json@vadl.local", password="Password123!@")
    token = auth.get_csrf_token("/scans")

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.elapsed.total_seconds.return_value = 0.05
    mock_resp.headers = {"X-Content-Type-Options": "nosniff"}
    mock_resp.cookies = []

    with patch("requests.Session.get", return_value=mock_resp):
        resp = client.post(
            "/scans/url",
            json={"target_url": "https://api-target.local"},
            headers={
                "Accept": "application/json",
                "X-CSRFToken": token,
            },
        )
        assert resp.status_code == 201
        data = resp.get_json()
        assert data["scanner_type"] == "URL_INSPECTOR"
        assert data["scan_mode"] == "URL"
        assert "score" in data
        assert "grade" in data
        assert "grade_breakdown" in data


def test_scan_zip_route_authenticated(client, auth):
    """Verify POST /scans/zip accepts zip upload and creates SecurityScan with score."""
    auth.create_user(
        email="analyst_zip@vadl.local",
        password="Password123!@",
        role=Role.SECURITY_ANALYST,
    )
    auth.login(email="analyst_zip@vadl.local", password="Password123!@")
    token = auth.get_csrf_token("/scans")

    zip_buf = _make_zip(
        {
            "app.py": "print('hello world')\n",
            "README.md": "Test project\n",
        }
    )

    resp = client.post(
        "/scans/zip",
        data={
            "csrf_token": token,
            "file": (zip_buf, "test_proj.zip"),
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert "GRADE" in html

    scan = SecurityScan.query.filter_by(scanner_type="ZIP_AUDIT").first()
    assert scan is not None
    assert scan.scan_mode == "ZIP"
    assert "test_proj.zip" in scan.target_url
    assert scan.score >= 90
    assert scan.grade in ("A+", "A")
