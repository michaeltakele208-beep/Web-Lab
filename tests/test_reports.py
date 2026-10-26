"""Automated tests for Phase 7 security assessment report generation, PDF compilation, and downloads."""

from app.extensions import db
from app.models.assessment import Assessment, TestResult
from app.models.lab import LabTarget
from app.models.report import SecurityReport
from app.models.scanner import NormalizedFinding, ScanAuditEvent, SecurityScan
from app.models.user import Role, User
from app.reports.pdf_generator import PdfReportGenerator
from app.reports.service import ReportService
from app.scanner.semantics import (
    FindingStatus,
    NormalizedSeverity,
    ScanAuditEventType,
    ScanLifecycle,
)


def test_reports_anonymous_redirect(client):
    """Verify anonymous access to reports console redirects to login."""
    resp = client.get("/reports")
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


def test_reports_ordinary_user_forbidden(client, auth):
    """Verify standard users without security analyst role receive 403 Forbidden."""
    auth.create_user(
        email="user_reports_denied@vadl.local", password="Password123!@", role=Role.USER
    )
    auth.login(email="user_reports_denied@vadl.local", password="Password123!@")
    resp = client.get("/reports")
    assert resp.status_code == 403


def test_reports_analyst_authorized(client, auth):
    """Verify security analyst receives 200 OK on reports console."""
    auth.create_user(
        email="analyst_reports_auth@vadl.local",
        password="Password123!@",
        role=Role.SECURITY_ANALYST,
    )
    auth.login(email="analyst_reports_auth@vadl.local", password="Password123!@")
    resp = client.get("/reports")
    assert resp.status_code == 200
    assert "Security Assessment Reports Repository" in resp.get_data(as_text=True)


def test_pdf_report_generation_for_scan_returns_valid_pdf(app, client, auth):
    """Verify compiling a SecurityScan PDF produces a valid PDF file starting with %PDF-."""
    with app.app_context():
        target = LabTarget(
            name="PDF Lab Target", base_url="http://127.0.0.1:5000/lab-pdf1", is_authorized=True
        )
        db.session.add(target)
        db.session.flush()

        analyst = auth.create_user(
            email="analyst_scan_pdf@vadl.local",
            password="Password123!@",
            role=Role.SECURITY_ANALYST,
        )

        scan = SecurityScan(
            scanner_type="bandit",
            scan_profile="baseline",
            status=ScanLifecycle.COMPLETED_WITH_FINDINGS.value,
            target_id=target.id,
            tool_version="1.8.3",
            initiated_by_user_id=analyst.id,
            total_findings=1,
            critical_count=1,
        )
        db.session.add(scan)
        db.session.flush()

        f = NormalizedFinding(
            scan_id=scan.id,
            scanner_name="bandit",
            tool_finding_id="B608",
            title="SQL Injection Detected in Route Handler",
            description="Direct string interpolation into raw SQL query allows parameter tampering.",
            severity=NormalizedSeverity.CRITICAL.value,
            confidence="HIGH",
            target_component="app/lab/vulnerable_routes.py",
            fingerprint="fp-pdf-test-001",
            status=FindingStatus.NEW.value,
            remediation_guidance="Use parameterized queries via SQLAlchemy query API.",
            evidence_snippet="SELECT * FROM products WHERE name = '" + "'; DROP TABLE users; --",
        )
        db.session.add(f)
        db.session.commit()
        scan_id = scan.id

    auth.login(email="analyst_scan_pdf@vadl.local", password="Password123!@")

    # Request PDF download route
    resp = client.get(f"/reports/scan/{scan_id}/pdf")
    assert resp.status_code in (200, 302)

    # If redirected, follow to download route
    if resp.status_code == 302:
        resp = client.get(resp.headers["Location"])

    assert resp.status_code == 200
    assert resp.content_type == "application/pdf"
    assert resp.data.startswith(b"%PDF-")
    assert len(resp.data) > 1000


def test_pdf_report_generation_for_assessment_returns_valid_pdf(app, client, auth):
    """Verify compiling an offensive Assessment PDF produces a valid PDF file."""
    with app.app_context():
        target = LabTarget(
            name="Assessment PDF Target",
            base_url="http://127.0.0.1:5000/lab-pdf2",
            is_authorized=True,
        )
        db.session.add(target)
        db.session.flush()

        analyst = auth.create_user(
            email="analyst_asm_pdf@vadl.local", password="Password123!@", role=Role.SECURITY_ANALYST
        )

        asm = Assessment(
            target_id=target.id,
            initiator_id=analyst.id,
            status="completed",
            selected_scenarios='["VADL-SQLI-001", "VADL-XSS-001"]',
            total_tests=2,
            confirmed_vulnerabilities=1,
            passed_checks=1,
        )
        db.session.add(asm)
        db.session.flush()

        r1 = TestResult(
            assessment_id=asm.id,
            scenario_id="VADL-SQLI-001",
            test_identifier="sqli_1",
            outcome="VULNERABILITY_CONFIRMED",
            target_edition="vulnerable",
            evidence="HTTP 200 returned payload with leaked secrets",
        )
        r2 = TestResult(
            assessment_id=asm.id,
            scenario_id="VADL-XSS-001",
            test_identifier="xss_1",
            outcome="SECURITY_CHECK_PASSED",
            target_edition="secure",
            evidence="HTML-encoded output: &lt;script&gt;",
        )
        db.session.add_all([r1, r2])
        db.session.commit()
        assessment_id = asm.id

    auth.login(email="analyst_asm_pdf@vadl.local", password="Password123!@")
    resp = client.get(f"/reports/assessment/{assessment_id}/pdf")
    if resp.status_code == 302:
        resp = client.get(resp.headers["Location"])

    assert resp.status_code == 200
    assert resp.content_type == "application/pdf"
    assert resp.data.startswith(b"%PDF-")


def test_json_report_generation(app, client, auth):
    """Verify machine-readable JSON report export returns valid JSON structure."""
    with app.app_context():
        target = LabTarget(
            name="JSON Target", base_url="http://127.0.0.1:5000/lab-json", is_authorized=True
        )
        db.session.add(target)
        db.session.flush()

        auth.create_user(
            email="analyst_json_rep@vadl.local",
            password="Password123!@",
            role=Role.SECURITY_ANALYST,
        )
        scan = SecurityScan(
            scanner_type="pip_audit",
            scan_profile="baseline",
            status="COMPLETED",
            target_id=target.id,
        )
        db.session.add(scan)
        db.session.commit()
        scan_id = scan.id

    auth.login(email="analyst_json_rep@vadl.local", password="Password123!@")
    resp = client.get(f"/reports/scan/{scan_id}/json")
    if resp.status_code == 302:
        resp = client.get(resp.headers["Location"])

    assert resp.status_code == 200
    assert "application/json" in resp.content_type
    data = resp.get_json()
    assert (
        data["report_metadata"]["project_name"] == "Vulnerability Assessment and Defense Lab (VADL)"
    )
    assert data["scan_execution"]["scanner_type"] == "pip_audit"


def test_report_download_endpoint_auditing(app, client, auth):
    """Verify downloading a report increments its download counter and records a ScanAuditEvent."""
    with app.app_context():
        analyst = auth.create_user(
            email="analyst_audit_rep@vadl.local",
            password="Password123!@",
            role=Role.SECURITY_ANALYST,
        )
        scan = SecurityScan(scanner_type="bandit", scan_profile="baseline", status="COMPLETED")
        db.session.add(scan)
        db.session.commit()

        report = ReportService.generate_scan_report(scan, actor=analyst, file_format="pdf")
        report_id = report.id
        scan_id = scan.id

    auth.login(email="analyst_audit_rep@vadl.local", password="Password123!@")
    resp = client.get(f"/reports/{report_id}/download")
    assert resp.status_code == 200

    with app.app_context():
        rep = db.session.get(SecurityReport, report_id)
        assert rep.download_count == 1

        ev = ScanAuditEvent.query.filter_by(
            scan_id=scan_id, event_type=ScanAuditEventType.REPORT_DOWNLOADED.value
        ).first()
        assert ev is not None
        assert f"Report #{report_id}" in ev.details


def test_report_download_path_traversal_rejection(app, client, auth):
    """Verify tampering with report file path to reference outside reports directory is rejected with 404."""
    with app.app_context():
        analyst = auth.create_user(
            email="analyst_trav_rep@vadl.local",
            password="Password123!@",
            role=Role.SECURITY_ANALYST,
        )
        malicious_report = SecurityReport(
            title="Malicious Path Traversal Report",
            report_type="SCAN",
            file_format="pdf",
            file_path="app/config.py",  # Outside reports/ directory
            generated_by_user_id=analyst.id,
        )
        db.session.add(malicious_report)
        db.session.commit()
        report_id = malicious_report.id

    auth.login(email="analyst_trav_rep@vadl.local", password="Password123!@")
    resp = client.get(f"/reports/{report_id}/download")
    assert resp.status_code == 404


def test_report_download_invalid_id_returns_404(client, auth):
    """Verify requesting non-existent report ID returns 404."""
    auth.create_user(
        email="analyst_notfound_rep@vadl.local",
        password="Password123!@",
        role=Role.SECURITY_ANALYST,
    )
    auth.login(email="analyst_notfound_rep@vadl.local", password="Password123!@")
    resp = client.get("/reports/999999/download")
    assert resp.status_code == 404


def test_report_generation_handles_malicious_control_characters(app):
    """Verify PDF generator safely escapes XML and HTML control tags without parser crash."""
    with app.app_context():
        analyst = User(
            email="sec@vadl.local", display_name="Security Analyst", role=Role.SECURITY_ANALYST
        )
        scan = SecurityScan(scanner_type="bandit", scan_profile="baseline", status="COMPLETED")
        db.session.add(scan)
        db.session.flush()

        # Finding with hostile XML/HTML tags
        f = NormalizedFinding(
            scan_id=scan.id,
            scanner_name="bandit",
            tool_finding_id="<script>alert(1)</script>",
            title="Injection & <font color='red'>Malicious XML Tag</font> & ' \"",
            description="<b>Bold</b> <unclosed tag & ampersand",
            severity="HIGH",
            target_component="<path/to/bad.py>",
            fingerprint="fp-safe-xml-001",
            status="NEW",
            evidence_snippet="<xml><script>attack()</script>&'\"",
        )
        db.session.add(f)
        db.session.commit()

        pdf_gen = PdfReportGenerator()
        pdf_bytes = pdf_gen.build_scan_pdf(scan, actor=analyst)
        assert pdf_bytes.startswith(b"%PDF-")


def test_report_generation_handles_long_findings_without_crashing(app):
    """Verify PDF generator handles multi-page descriptions and oversized evidence cleanly."""
    with app.app_context():
        analyst = User(
            email="sec2@vadl.local", display_name="Security Analyst 2", role=Role.SECURITY_ANALYST
        )
        scan = SecurityScan(scanner_type="bandit", scan_profile="baseline", status="COMPLETED")
        db.session.add(scan)
        db.session.flush()

        long_description = "Extremely long diagnostic explanation. " * 250
        long_evidence = (
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nPayload data chunk...\n" * 50
        )

        f = NormalizedFinding(
            scan_id=scan.id,
            scanner_name="bandit",
            tool_finding_id="B999",
            title="Large Payload Finding",
            description=long_description,
            severity="MEDIUM",
            target_component="app/long_module.py",
            fingerprint="fp-long-001",
            status="NEW",
            evidence_snippet=long_evidence,
        )
        db.session.add(f)
        db.session.commit()

        pdf_gen = PdfReportGenerator()
        pdf_bytes = pdf_gen.build_scan_pdf(scan, actor=analyst)
        assert pdf_bytes.startswith(b"%PDF-")
