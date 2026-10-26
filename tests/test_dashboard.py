"""Automated tests for Phase 7 Security Operations Dashboard, metrics integrity, and filtering."""

from app.extensions import db
from app.models.assessment import Assessment, TestResult
from app.models.lab import LabTarget
from app.models.remediation import Remediation
from app.models.scanner import NormalizedFinding, SecurityScan
from app.models.user import Role
from app.scanner.semantics import FindingStatus, NormalizedSeverity, ScanLifecycle


def test_dashboard_anonymous_renders_public_view(client):
    """Verify anonymous access renders public lab dashboard with zero-data empty states."""
    resp = client.get("/")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert "Security Operations Dashboard" in html
    assert "Unauthenticated Guest Session" in html


def test_dashboard_empty_database_produces_empty_states(client, auth):
    """Verify an empty database displays zero metrics without crashing."""
    auth.create_user(
        email="analyst_dash_empty@vadl.local", password="Password123!@", role=Role.SECURITY_ANALYST
    )
    auth.login(email="analyst_dash_empty@vadl.local", password="Password123!@")

    resp = client.get("/dashboard")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert "Security Operations Dashboard" in html
    assert "No scans or assessments recorded matching the current filters." in html
    assert "No normalized findings match the current criteria." in html
    assert "No remediation tracks currently created." in html


def test_dashboard_metrics_match_persisted_database_records(app, client, auth):
    """Verify dashboard metrics precisely calculate totals from persisted records."""
    with app.app_context():
        target = LabTarget(
            name="Dashboard Target", base_url="http://127.0.0.1:5000/lab", is_authorized=True
        )
        db.session.add(target)
        db.session.flush()

        analyst = auth.create_user(
            email="analyst_dash_metrics@vadl.local",
            password="Password123!@",
            role=Role.SECURITY_ANALYST,
        )

        # 1. Successful Scan
        scan_ok = SecurityScan(
            scanner_type="bandit",
            scan_profile="baseline",
            status=ScanLifecycle.COMPLETED_WITH_FINDINGS.value,
            initiated_by_user_id=analyst.id,
            target_id=target.id,
            total_findings=2,
            critical_count=1,
            high_count=1,
        )
        # 2. Failed Scan
        scan_failed = SecurityScan(
            scanner_type="zap",
            scan_profile="baseline",
            status=ScanLifecycle.FAILED.value,
            initiated_by_user_id=analyst.id,
            target_id=target.id,
            total_findings=0,
        )
        db.session.add_all([scan_ok, scan_failed])
        db.session.flush()

        # Findings
        f1 = NormalizedFinding(
            scan_id=scan_ok.id,
            scanner_name="bandit",
            tool_finding_id="B608",
            title="SQL Injection Finding",
            description="Potential SQL injection detected",
            severity=NormalizedSeverity.CRITICAL.value,
            confidence="HIGH",
            target_component="app/routes/vuln.py",
            fingerprint="fp-dash-001",
            status=FindingStatus.NEW.value,
        )
        f2 = NormalizedFinding(
            scan_id=scan_ok.id,
            scanner_name="bandit",
            tool_finding_id="B701",
            title="XSS Flaw Finding",
            description="Missing escaping",
            severity=NormalizedSeverity.HIGH.value,
            confidence="HIGH",
            target_component="app/templates/vuln.html",
            fingerprint="fp-dash-002",
            status=FindingStatus.ACTIVE.value,
        )
        db.session.add_all([f1, f2])

        # Assessment
        asm = Assessment(
            target_id=target.id,
            initiator_id=analyst.id,
            status="completed",
            selected_scenarios='["VADL-SQLI-001"]',
            total_tests=1,
            confirmed_vulnerabilities=1,
        )
        db.session.add(asm)
        db.session.flush()

        tr = TestResult(
            assessment_id=asm.id,
            scenario_id="VADL-SQLI-001",
            test_identifier="sqli_probe_1",
            target_edition="vulnerable",
            outcome="VULNERABILITY_CONFIRMED",
        )
        db.session.add(tr)

        # Remediations
        rem_verified = Remediation(
            scenario_id="VADL-SQLI-001",
            title="Fix SQLi",
            status="VERIFIED",
            verification_status="VERIFIED",
        )
        rem_pending = Remediation(
            scenario_id="VADL-XSS-001",
            title="Fix XSS",
            status="OPEN",
            verification_status="UNVERIFIED",
        )
        db.session.add_all([rem_verified, rem_pending])
        db.session.commit()

    auth.login(email="analyst_dash_metrics@vadl.local", password="Password123!@")

    # Inspect JSON metrics endpoint
    resp = client.get("/dashboard", headers={"Accept": "application/json"})
    assert resp.status_code == 200
    data = resp.get_json()["metrics"]

    assert data["total_scans"] == 3  # 2 security scans + 1 assessment
    assert data["completed_scans"] == 2  # 1 completed scan + 1 completed assessment
    assert data["failed_scans"] == 1  # 1 failed scan
    assert data["total_distinct_findings"] == 2
    assert data["open_findings"] == 2
    assert data["confirmed_vulnerabilities"] == 1
    assert data["verified_remediations"] == 1
    assert data["pending_remediations"] == 1
    assert data["severity_counts"]["CRITICAL"] == 1
    assert data["severity_counts"]["HIGH"] == 1
    assert data["severity_counts"]["MEDIUM"] == 0


def test_dashboard_avoids_double_counting_findings(app, client, auth):
    """Verify recurring scans observing the same fingerprint do not inflate distinct vulnerability count."""
    with app.app_context():
        target = LabTarget(
            name="Deduplication Target",
            base_url="http://127.0.0.1:5000/lab-dedup",
            is_authorized=True,
        )
        db.session.add(target)
        db.session.flush()

        auth.create_user(
            email="analyst_dash_dedup@vadl.local",
            password="Password123!@",
            role=Role.SECURITY_ANALYST,
        )

        # Scan 1
        s1 = SecurityScan(
            scanner_type="bandit",
            scan_profile="baseline",
            status="COMPLETED_WITH_FINDINGS",
            target_id=target.id,
        )
        # Scan 2
        s2 = SecurityScan(
            scanner_type="bandit",
            scan_profile="baseline",
            status="COMPLETED_WITH_FINDINGS",
            target_id=target.id,
        )
        db.session.add_all([s1, s2])
        db.session.flush()

        # Same fingerprint in both scans
        shared_fp = "stable-sha256-fingerprint-999"
        f1 = NormalizedFinding(
            scan_id=s1.id,
            scanner_name="bandit",
            tool_finding_id="B608",
            title="Recurring Injection",
            description="Test",
            severity=NormalizedSeverity.HIGH.value,
            fingerprint=shared_fp,
            status=FindingStatus.ACTIVE.value,
            target_component="app/vuln.py",
        )
        f2 = NormalizedFinding(
            scan_id=s2.id,
            scanner_name="bandit",
            tool_finding_id="B608",
            title="Recurring Injection",
            description="Test",
            severity=NormalizedSeverity.HIGH.value,
            fingerprint=shared_fp,
            status=FindingStatus.ACTIVE.value,
            target_component="app/vuln.py",
        )
        db.session.add_all([f1, f2])
        db.session.commit()

    auth.login(email="analyst_dash_dedup@vadl.local", password="Password123!@")
    resp = client.get("/dashboard", headers={"Accept": "application/json"})
    assert resp.status_code == 200
    metrics = resp.get_json()["metrics"]

    assert metrics["total_distinct_findings"] == 1
    assert metrics["total_finding_records"] == 2


def test_dashboard_filtering_and_pagination(client, auth):
    """Verify filter parameters in dashboard query string return expected subsets."""
    auth.create_user(
        email="analyst_dash_filter@vadl.local", password="Password123!@", role=Role.SECURITY_ANALYST
    )
    auth.login(email="analyst_dash_filter@vadl.local", password="Password123!@")

    # Filter scan type
    resp_scanners = client.get("/dashboard?scan_type=scanner")
    assert resp_scanners.status_code == 200

    resp_assessments = client.get("/dashboard?scan_type=assessment")
    assert resp_assessments.status_code == 200

    # Filter findings
    resp_crit = client.get("/dashboard?severity=CRITICAL")
    assert resp_crit.status_code == 200
