"""Automated tests for Phase 4 offensive testing engine scenario adapters."""

import pytest

from app.engine.adapters import (
    IDORAdapter,
    SecurityHeadersAdapter,
    SQLInjectionAdapter,
    XSSAdapter,
    get_adapter,
    get_supported_scenarios,
)
from app.engine.semantics import ResultOutcome
from app.models.lab import LabTarget


@pytest.fixture
def authorized_lab_target(app):
    """Fixture providing an authorized local lab target."""
    with app.app_context():
        target = LabTarget.query.filter_by(base_url="http://127.0.0.1:5000/lab").first()
        if not target:
            target = LabTarget(
                name="Local Test Sandbox",
                base_url="http://127.0.0.1:5000/lab",
                environment_id="testing",
                is_authorized=True,
            )
            from app.extensions import db

            db.session.add(target)
            db.session.commit()
        return target


def test_adapter_registry_contains_all_four_scenarios():
    """Verify all four registered scenarios have mapped adapters in the allowlist."""
    supported = get_supported_scenarios()
    expected = ["VADL-SQLI-001", "VADL-XSS-001", "VADL-AC-001", "VADL-HEADERS-001"]
    for scen in expected:
        assert scen in supported
        adapter = get_adapter(scen)
        assert adapter is not None
        assert adapter.scenario_id == scen


def test_sqli_adapter_evaluates_vulnerable_and_secure_editions(
    client, authorized_lab_target, lab_seed
):
    """Verify SQL injection adapter reproduces flaw in vulnerable edition and verifies defense in secure."""
    adapter = SQLInjectionAdapter()

    # 1. Test vulnerable edition
    res_vuln = adapter.execute(authorized_lab_target, "vulnerable", client)
    assert res_vuln.scenario_id == "VADL-SQLI-001"
    assert res_vuln.target_edition == "vulnerable"
    assert res_vuln.outcome == ResultOutcome.VULNERABILITY_CONFIRMED
    assert "CONFIDENTIAL_LAB_FLAG" in res_vuln.evidence

    # 2. Test secure edition
    res_sec = adapter.execute(authorized_lab_target, "secure", client)
    assert res_sec.scenario_id == "VADL-SQLI-001"
    assert res_sec.target_edition == "secure"
    assert res_sec.outcome == ResultOutcome.SECURITY_CHECK_PASSED
    assert "CONFIDENTIAL_LAB_FLAG" not in res_sec.evidence


def test_xss_adapter_evaluates_vulnerable_and_secure_editions(
    client, authorized_lab_target, lab_seed
):
    """Verify XSS adapter detects unescaped markup in vulnerable edition and encodes in secure."""
    adapter = XSSAdapter()

    # 1. Test vulnerable edition (Markup unescaped bypass)
    res_vuln = adapter.execute(authorized_lab_target, "vulnerable", client)
    assert res_vuln.scenario_id == "VADL-XSS-001"
    assert res_vuln.target_edition == "vulnerable"
    assert res_vuln.outcome == ResultOutcome.VULNERABILITY_CONFIRMED
    assert "Raw HTML markup was rendered unescaped" in res_vuln.evidence

    # 2. Test secure edition (Jinja contextual entity encoding)
    res_sec = adapter.execute(authorized_lab_target, "secure", client)
    assert res_sec.scenario_id == "VADL-XSS-001"
    assert res_sec.target_edition == "secure"
    assert res_sec.outcome == ResultOutcome.SECURITY_CHECK_PASSED
    assert "&lt;span" in res_sec.evidence


def test_idor_adapter_evaluates_vulnerable_and_secure_editions(
    client, authorized_lab_target, lab_seed
):
    """Verify IDOR adapter detects missing ownership check on vulnerable and validates 403 on secure."""
    adapter = IDORAdapter()

    # 1. Test vulnerable edition (direct PK access)
    res_vuln = adapter.execute(authorized_lab_target, "vulnerable", client)
    assert res_vuln.scenario_id == "VADL-AC-001"
    assert res_vuln.target_edition == "vulnerable"
    assert res_vuln.outcome == ResultOutcome.VULNERABILITY_CONFIRMED
    assert "Direct object reference allowed unauthorized retrieval" in res_vuln.evidence

    # 2. Test secure edition (ownership validation)
    res_sec = adapter.execute(authorized_lab_target, "secure", client)
    assert res_sec.scenario_id == "VADL-AC-001"
    assert res_sec.target_edition == "secure"
    assert res_sec.outcome == ResultOutcome.SECURITY_CHECK_PASSED
    assert "403 Forbidden" in res_sec.evidence


def test_headers_adapter_evaluates_vulnerable_and_secure_editions(client, authorized_lab_target):
    """Verify Security Headers adapter detects missing headers on vulnerable and validates secure posture."""
    adapter = SecurityHeadersAdapter()

    # 1. Test vulnerable edition (omitted security headers)
    res_vuln = adapter.execute(authorized_lab_target, "vulnerable", client)
    assert res_vuln.scenario_id == "VADL-HEADERS-001"
    assert res_vuln.target_edition == "vulnerable"
    assert res_vuln.outcome == ResultOutcome.VULNERABILITY_CONFIRMED
    assert "omits vital defensive security headers" in res_vuln.evidence

    # 2. Test secure edition (defensive headers configured)
    res_sec = adapter.execute(authorized_lab_target, "secure", client)
    assert res_sec.scenario_id == "VADL-HEADERS-001"
    assert res_sec.target_edition == "secure"
    assert res_sec.outcome == ResultOutcome.SECURITY_CHECK_PASSED
    assert "All required defensive security headers are correctly configured" in res_sec.evidence
