"""Automated tests for Phase 7 scan differential comparison engine and trend reporting."""

import pytest

from app.extensions import db
from app.models.assessment import Assessment, TestResult
from app.models.lab import LabTarget
from app.models.scanner import NormalizedFinding, SecurityScan
from app.models.user import Role
from app.reports.comparison_service import ScanComparisonService
from app.scanner.semantics import FindingStatus, NormalizedSeverity, ScanLifecycle


def test_scan_comparison_classifies_new_resolved_persistent(app):
    """Verify comparison correctly categorizes newly detected, resolved, and persistent findings."""
    with app.app_context():
        target = LabTarget(
            name="Comparison Target", base_url="http://127.0.0.1:5000/lab1", is_authorized=True
        )
        db.session.add(target)
        db.session.flush()

        # Baseline Scan (Scan A)
        scan_a = SecurityScan(
            scanner_type="bandit",
            scan_profile="baseline",
            status=ScanLifecycle.COMPLETED.value,
            target_id=target.id,
        )
        # Comparison Scan (Scan B)
        scan_b = SecurityScan(
            scanner_type="bandit",
            scan_profile="baseline",
            status=ScanLifecycle.COMPLETED.value,
            target_id=target.id,
        )
        db.session.add_all([scan_a, scan_b])
        db.session.flush()

        # Findings:
        # fp-persist: in both A and B
        # fp-resolved: in A only
        # fp-new: in B only
        fa_persist = NormalizedFinding(
            scan_id=scan_a.id,
            scanner_name="bandit",
            tool_finding_id="B1",
            title="Persistent Flaw",
            description="",
            severity=NormalizedSeverity.HIGH.value,
            fingerprint="fp-persist",
            status=FindingStatus.ACTIVE.value,
            target_component="app/a.py",
        )
        fa_resolved = NormalizedFinding(
            scan_id=scan_a.id,
            scanner_name="bandit",
            tool_finding_id="B2",
            title="Resolved Flaw",
            description="",
            severity=NormalizedSeverity.MEDIUM.value,
            fingerprint="fp-resolved",
            status=FindingStatus.ACTIVE.value,
            target_component="app/b.py",
        )
        fb_persist = NormalizedFinding(
            scan_id=scan_b.id,
            scanner_name="bandit",
            tool_finding_id="B1",
            title="Persistent Flaw",
            description="",
            severity=NormalizedSeverity.HIGH.value,
            fingerprint="fp-persist",
            status=FindingStatus.ACTIVE.value,
            target_component="app/a.py",
        )
        fb_new = NormalizedFinding(
            scan_id=scan_b.id,
            scanner_name="bandit",
            tool_finding_id="B3",
            title="New Flaw",
            description="",
            severity=NormalizedSeverity.CRITICAL.value,
            fingerprint="fp-new",
            status=FindingStatus.NEW.value,
            target_component="app/c.py",
        )
        db.session.add_all([fa_persist, fa_resolved, fb_persist, fb_new])
        db.session.commit()

        diff = ScanComparisonService.compare_security_scans(scan_a, scan_b)

        assert diff["is_conclusive"] is True
        assert diff["counts"]["new"] == 1
        assert diff["counts"]["resolved"] == 1
        assert diff["counts"]["persistent"] == 1
        assert diff["counts"]["severity_changes"] == 0

        assert diff["new_findings"][0].fingerprint == "fp-new"
        assert diff["resolved_findings"][0].fingerprint == "fp-resolved"
        assert diff["persistent_findings"][0].fingerprint == "fp-persist"


def test_scan_comparison_detects_severity_changes(app):
    """Verify persistent findings with altered severity ratings are flagged."""
    with app.app_context():
        target = LabTarget(
            name="Severity Target", base_url="http://127.0.0.1:5000/lab2", is_authorized=True
        )
        db.session.add(target)
        db.session.flush()

        scan_a = SecurityScan(
            scanner_type="bandit", scan_profile="baseline", status="COMPLETED", target_id=target.id
        )
        scan_b = SecurityScan(
            scanner_type="bandit", scan_profile="baseline", status="COMPLETED", target_id=target.id
        )
        db.session.add_all([scan_a, scan_b])
        db.session.flush()

        fa = NormalizedFinding(
            scan_id=scan_a.id,
            scanner_name="bandit",
            tool_finding_id="B1",
            title="Escalating Issue",
            description="",
            severity=NormalizedSeverity.MEDIUM.value,
            fingerprint="fp-escalate",
            status=FindingStatus.ACTIVE.value,
            target_component="app/vuln.py",
        )
        fb = NormalizedFinding(
            scan_id=scan_b.id,
            scanner_name="bandit",
            tool_finding_id="B1",
            title="Escalating Issue",
            description="",
            severity=NormalizedSeverity.HIGH.value,
            fingerprint="fp-escalate",
            status=FindingStatus.ACTIVE.value,
            target_component="app/vuln.py",
        )
        db.session.add_all([fa, fb])
        db.session.commit()

        diff = ScanComparisonService.compare_security_scans(scan_a, scan_b)
        assert diff["counts"]["severity_changes"] == 1
        ch = diff["severity_changes"][0]
        assert ch["old_severity"] == "MEDIUM"
        assert ch["new_severity"] == "HIGH"


def test_scan_comparison_rejects_differing_targets(app):
    """Verify comparisons across differing target IDs are rejected."""
    with app.app_context():
        t1 = LabTarget(name="Target 1", base_url="http://127.0.0.1:5000/lab-t1", is_authorized=True)
        t2 = LabTarget(name="Target 2", base_url="http://127.0.0.1:5000/lab-t2", is_authorized=True)
        db.session.add_all([t1, t2])
        db.session.flush()

        scan_1 = SecurityScan(
            scanner_type="bandit", scan_profile="baseline", status="COMPLETED", target_id=t1.id
        )
        scan_2 = SecurityScan(
            scanner_type="bandit", scan_profile="baseline", status="COMPLETED", target_id=t2.id
        )
        db.session.add_all([scan_1, scan_2])
        db.session.commit()

        with pytest.raises(ValueError, match="Cannot compare scans across differing lab targets"):
            ScanComparisonService.compare_security_scans(scan_1, scan_2)


def test_scan_comparison_flags_incomplete_or_failed_scans_as_inconclusive(app):
    """Verify comparisons involving failed or timed-out scans are marked inconclusive with explicit caveats."""
    with app.app_context():
        target = LabTarget(
            name="Caveat Target", base_url="http://127.0.0.1:5000/lab-caveat", is_authorized=True
        )
        db.session.add(target)
        db.session.flush()

        scan_ok = SecurityScan(
            scanner_type="bandit", scan_profile="baseline", status="COMPLETED", target_id=target.id
        )
        scan_failed = SecurityScan(
            scanner_type="bandit", scan_profile="baseline", status="FAILED", target_id=target.id
        )
        db.session.add_all([scan_ok, scan_failed])
        db.session.commit()

        diff = ScanComparisonService.compare_security_scans(scan_ok, scan_failed)
        assert diff["is_conclusive"] is False
        assert any("FAILED" in c for c in diff["caveats"])


def test_assessment_comparison_classifies_remediated_and_new_flaws(app):
    """Verify comparing two offensive assessments correctly categorizes remediated and new vulnerabilities."""
    with app.app_context():
        target = LabTarget(
            name="Asm Comp Target", base_url="http://127.0.0.1:5000/lab-asm", is_authorized=True
        )
        db.session.add(target)
        db.session.flush()

        asm1 = Assessment(target_id=target.id, status="completed", selected_scenarios="[]")
        asm2 = Assessment(target_id=target.id, status="completed", selected_scenarios="[]")
        db.session.add_all([asm1, asm2])
        db.session.flush()

        # In asm1: SQLI is vulnerable, XSS is passed
        # In asm2: SQLI is passed (remediated!), XSS is vulnerable (new flaw!)
        r1_sqli = TestResult(
            assessment_id=asm1.id,
            scenario_id="VADL-SQLI-001",
            test_identifier="t_sqli",
            target_edition="vulnerable",
            outcome="VULNERABILITY_CONFIRMED",
        )
        r1_xss = TestResult(
            assessment_id=asm1.id,
            scenario_id="VADL-XSS-001",
            test_identifier="t_xss",
            target_edition="secure",
            outcome="SECURITY_CHECK_PASSED",
        )
        r2_sqli = TestResult(
            assessment_id=asm2.id,
            scenario_id="VADL-SQLI-001",
            test_identifier="t_sqli",
            target_edition="secure",
            outcome="SECURITY_CHECK_PASSED",
        )
        r2_xss = TestResult(
            assessment_id=asm2.id,
            scenario_id="VADL-XSS-001",
            test_identifier="t_xss",
            target_edition="vulnerable",
            outcome="VULNERABILITY_CONFIRMED",
        )
        db.session.add_all([r1_sqli, r1_xss, r2_sqli, r2_xss])
        db.session.commit()

        diff = ScanComparisonService.compare_assessments(asm1, asm2)
        assert diff["counts"]["remediated"] == 1
        assert diff["counts"]["new"] == 1
        assert diff["remediated_scenarios"][0]["scenario_id"] == "VADL-SQLI-001"
        assert diff["new_vulnerabilities"][0]["scenario_id"] == "VADL-XSS-001"


def test_comparison_web_and_json_routes(app, client, auth):
    """Verify /reports/compare web interface and JSON API."""
    with app.app_context():
        target = LabTarget(
            name="Route Comp Target", base_url="http://127.0.0.1:5000/lab-route", is_authorized=True
        )
        db.session.add(target)
        db.session.flush()

        auth.create_user(
            email="analyst_comp_route@vadl.local",
            password="Password123!@",
            role=Role.SECURITY_ANALYST,
        )
        s1 = SecurityScan(
            scanner_type="bandit", scan_profile="baseline", status="COMPLETED", target_id=target.id
        )
        s2 = SecurityScan(
            scanner_type="bandit", scan_profile="baseline", status="COMPLETED", target_id=target.id
        )
        db.session.add_all([s1, s2])
        db.session.commit()
        s1_id = s1.id
        s2_id = s2.id

    auth.login(email="analyst_comp_route@vadl.local", password="Password123!@")

    # 1. GET page
    resp = client.get("/reports/compare")
    assert resp.status_code == 200
    assert "Scan Differential Comparison Console" in resp.get_data(as_text=True)

    # 2. JSON API
    resp_json = client.get(
        f"/reports/compare?scan_a_id={s1_id}&scan_b_id={s2_id}",
        headers={"Accept": "application/json"},
    )
    assert resp_json.status_code == 200
    data = resp_json.get_json()
    assert data["comparison_type"] == "security_scan"
    assert "counts" in data
