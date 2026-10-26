"""Automated tests for Phase 3 laboratory isolation, scenario registry, and target authorization boundaries."""

import socket
from unittest.mock import patch

import pytest

from app import create_app
from app.config import get_config
from app.extensions import db
from app.lab.registry import get_all_scenarios, get_scenario
from app.lab.target_validator import validate_lab_target_url
from app.models.lab import LabTarget
from app.models.user import Role


def test_vulnerable_mode_refuses_startup_under_production_config(monkeypatch):
    """Verify application startup strictly refuses to boot if vulnerable lab is requested in production."""
    monkeypatch.setenv("SECRET_KEY", "a" * 32)
    monkeypatch.setenv("FLASK_CONFIG", "production")
    monkeypatch.setenv("VADL_ENABLE_VULNERABLE_LAB", "true")

    with pytest.raises(ValueError, match="CRITICAL SECURITY VIOLATION"):
        get_config("production")

    with pytest.raises(ValueError, match="CRITICAL SECURITY VIOLATION"):
        create_app("production")


def test_vulnerable_edition_disabled_when_flag_is_false(monkeypatch):
    """Verify accessing vulnerable lab routes returns HTTP 404 when ENABLE_VULNERABLE_LAB is disabled."""
    monkeypatch.setenv("VADL_ENABLE_VULNERABLE_LAB", "false")
    app = create_app("testing")
    app.config["ENABLE_VULNERABLE_LAB"] = False

    test_client = app.test_client()
    resp_index = test_client.get("/lab/vulnerable")
    assert resp_index.status_code == 404

    resp_sqli = test_client.get("/lab/vulnerable/sqli")
    assert resp_sqli.status_code == 404


def test_scenario_registry_integrity():
    """Verify the scenario registry contains all 4 documented scenarios with complete metadata."""
    scenarios = get_all_scenarios()
    assert len(scenarios) >= 4

    scenario_ids = {s.scenario_id for s in scenarios}
    expected_ids = {"VADL-SQLI-001", "VADL-XSS-001", "VADL-AC-001", "VADL-HEADERS-001"}
    assert expected_ids.issubset(scenario_ids)

    for s_id in expected_ids:
        scenario = get_scenario(s_id)
        assert scenario is not None
        assert scenario.title != ""
        assert scenario.category != ""
        assert scenario.severity in ("HIGH", "MEDIUM", "LOW")
        assert scenario.remediation != ""
        assert len(scenario.reproduction_steps) > 0
        assert scenario.status == "not_assessed"  # Initial state driven by test evidence


def test_target_url_allowlist_validation():
    """Verify target allowlist accepts approved lab hosts and rejects arbitrary internet destinations."""
    # Approved internal lab hosts
    valid_targets = [
        "http://127.0.0.1:5000",
        "http://127.0.0.1:5000/lab",
        "http://localhost:5000/lab/vulnerable",
        "http://vadl-app:5000",
        "http://vadl-vulnerable-app:5000",
        "https://vadl-target:8443",
    ]
    for url in valid_targets:
        is_valid, msg = validate_lab_target_url(url)
        assert is_valid is True, f"Expected '{url}' to be valid, got: {msg}"

    # Rejected public / arbitrary destinations
    invalid_targets = [
        "https://google.com",
        "http://example.org/scanner",
        "http://8.8.8.8:8080",
        "http://169.254.169.254/latest/meta-data",  # Cloud metadata IP
        "ftp://127.0.0.1/pub",  # Disallowed scheme
        "file:///etc/passwd",  # Disallowed scheme
        "javascript:alert(1)",  # Disallowed scheme
        "",
        None,
    ]
    for url in invalid_targets:
        is_valid, _ = validate_lab_target_url(url)
        assert is_valid is False, f"Expected '{url}' to be rejected as an unapproved target."


def test_target_registration_does_not_make_network_requests():
    """Verify target registration validates syntax purely offline and never probes destinations."""

    def fail_on_network(*args, **kwargs):
        raise AssertionError(
            "Target validation attempted an unexpected outbound socket connection!"
        )

    with patch.object(socket, "socket", side_effect=fail_on_network):
        is_valid, _ = validate_lab_target_url("http://127.0.0.1:5000/lab")
        assert is_valid is True


def test_analyst_cannot_manage_targets(client, auth):
    """Verify security analyst and anonymous users cannot access or modify target registry."""
    # Anonymous access is redirected
    resp_anon = client.get("/admin/lab")
    assert resp_anon.status_code == 302
    assert "/login" in resp_anon.headers["Location"]

    # Security analyst cannot access or post targets
    auth.create_user(
        email="analyst@vadl.local", password="Password123!@", role=Role.SECURITY_ANALYST
    )
    auth.login(email="analyst@vadl.local", password="Password123!@")

    resp_analyst_view = client.get("/admin/lab")
    assert resp_analyst_view.status_code == 403

    token = auth.get_csrf_token("/profile")
    resp_analyst_post = client.post(
        "/admin/lab/targets",
        data={
            "name": "Unauthorized Target",
            "base_url": "http://127.0.0.1:5000/lab",
            "csrf_token": token,
        },
    )
    assert resp_analyst_post.status_code == 403

    # Analyst CAN view assessment console in read-only mode
    resp_assess = client.get("/assessments")
    assert resp_assess.status_code == 200


def test_admin_can_manage_targets(client, auth):
    """Verify administrator account can register, authorize, and toggle targets."""
    auth.create_user(email="admin@vadl.local", password="Password123!@", role=Role.ADMIN)
    auth.login(email="admin@vadl.local", password="Password123!@")

    # Admin accesses lab console
    resp_admin = client.get("/admin/lab")
    assert resp_admin.status_code == 200
    assert "Laboratory &amp; Target Management" in resp_admin.get_data(as_text=True)

    # Admin registers authorized target
    admin_token = auth.get_csrf_token("/admin/lab")
    resp_register = client.post(
        "/admin/lab/targets",
        data={
            "name": "Local Sandbox Instance",
            "target_type": "internal_lab_edition",
            "environment_id": "development",
            "base_url": "http://127.0.0.1:5000/lab",
            "csrf_token": admin_token,
        },
        follow_redirects=True,
    )
    assert resp_register.status_code == 200
    assert "Successfully registered and authorized target" in resp_register.get_data(as_text=True)

    target = LabTarget.query.filter_by(base_url="http://127.0.0.1:5000/lab").first()
    assert target is not None
    assert target.is_authorized is True

    # Admin toggles authorization status
    resp_toggle = client.post(
        f"/admin/lab/targets/{target.id}/toggle",
        data={"csrf_token": admin_token},
        follow_redirects=True,
    )
    assert resp_toggle.status_code == 200
    refreshed_target = db.session.get(LabTarget, target.id)
    assert refreshed_target.is_authorized is False
