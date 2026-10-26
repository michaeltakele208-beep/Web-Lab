"""Automated tests for Phase 6 scanner web routes, UI templates, and JSON APIs."""

from pathlib import Path

from app.extensions import db
from app.models.scanner import NormalizedFinding, SecurityScan
from app.models.user import Role
from app.scanner.semantics import NormalizedSeverity, ScanLifecycle


def test_scans_anonymous_redirect(client):
    """Verify anonymous access to scanner console redirects to login."""
    resp = client.get("/scans")
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


def test_scans_ordinary_user_forbidden(client, auth):
    """Verify ordinary users receive HTTP 403 Forbidden on scanner console."""
    auth.create_user(email="user_scan_route@vadl.local", password="Password123!@", role=Role.USER)
    auth.login(email="user_scan_route@vadl.local", password="Password123!@")
    resp = client.get("/scans")
    assert resp.status_code == 403


def test_scans_analyst_authorized(client, auth):
    """Verify security analyst receives HTTP 200 OK on scanner console."""
    auth.create_user(
        email="analyst_scan_route@vadl.local", password="Password123!@", role=Role.SECURITY_ANALYST
    )
    auth.login(email="analyst_scan_route@vadl.local", password="Password123!@")
    resp = client.get("/scans")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert "Automated Security Scanning Console" in html
    assert "Execute Automated Security Scan" in html


def test_run_scan_via_web_form(client, auth):
    """Verify triggering Bandit scan via web form with valid CSRF token."""
    auth.create_user(
        email="analyst_form_scan@vadl.local", password="Password123!@", role=Role.SECURITY_ANALYST
    )
    auth.login(email="analyst_form_scan@vadl.local", password="Password123!@")
    token = auth.get_csrf_token("/scans")

    resp = client.post(
        "/scans/run",
        data={
            "scanner_type": "bandit",
            "source_dir": "app",
            "profile": "baseline",
            "csrf_token": token,
        },
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert "/scans/" in resp.headers["Location"]


def test_run_scan_rejects_missing_csrf_token(client, auth):
    """Verify state-changing scan initiation fails when CSRF token is missing."""
    auth.create_user(
        email="analyst_no_csrf@vadl.local", password="Password123!@", role=Role.SECURITY_ANALYST
    )
    auth.login(email="analyst_no_csrf@vadl.local", password="Password123!@")

    resp = client.post(
        "/scans/run",
        data={
            "scanner_type": "bandit",
            "source_dir": "app",
        },
    )
    assert resp.status_code == 400
    assert "CSRF verification failed" in resp.get_data(as_text=True)


def test_run_scan_via_json_api(client, auth):
    """Verify triggering scan via JSON API with X-CSRF-Token returns HTTP 201 Created."""
    auth.create_user(
        email="analyst_json_scan@vadl.local", password="Password123!@", role=Role.SECURITY_ANALYST
    )
    auth.login(email="analyst_json_scan@vadl.local", password="Password123!@")
    token = auth.get_csrf_token("/scans")

    resp = client.post(
        "/scans/run",
        json={
            "scanner_type": "bandit",
            "source_dir": "app",
            "profile": "baseline",
        },
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-CSRF-Token": token,
        },
    )
    assert resp.status_code == 201
    data = resp.get_json()
    assert "id" in data
    assert data["scanner_type"] == "bandit"
    assert data["status"] in ("COMPLETED", "COMPLETED_WITH_FINDINGS")


def test_scan_detail_and_report_download(app, client, auth, tmp_path):
    """Verify viewing scan details and downloading the raw JSON report artifact."""
    with app.app_context():
        analyst = auth.create_user(
            email="analyst_detail_scan@vadl.local",
            password="Password123!@",
            role=Role.SECURITY_ANALYST,
        )

        # Create mock report file in reports/scans
        reports_dir = Path("reports/scans")
        reports_dir.mkdir(parents=True, exist_ok=True)
        report_file = reports_dir / "test_report_download.json"
        report_file.write_text('{"tool": "bandit", "results": []}', encoding="utf-8")

        scan = SecurityScan(
            scanner_type="bandit",
            scan_profile="baseline",
            status=ScanLifecycle.COMPLETED.value,
            initiated_by_user_id=analyst.id,
            tool_version="1.8.3",
            raw_report_path=str(report_file),
        )
        db.session.add(scan)
        db.session.commit()
        scan_id = scan.id

    auth.login(email="analyst_detail_scan@vadl.local", password="Password123!@")

    # 1. Inspect detail view
    resp_detail = client.get(f"/scans/{scan_id}")
    assert resp_detail.status_code == 200
    assert "Scan Run Overview" in resp_detail.get_data(as_text=True)

    # 2. Download report artifact
    resp_download = client.get(f"/scans/{scan_id}/report")
    assert resp_download.status_code == 200
    assert resp_download.mimetype == "application/json"
    assert b"tool" in resp_download.data


def test_findings_list_and_filters(app, client, auth):
    """Verify filtering findings by severity, scanner, and search query."""
    with app.app_context():
        analyst = auth.create_user(
            email="analyst_filter_test@vadl.local",
            password="Password123!@",
            role=Role.SECURITY_ANALYST,
        )
        scan = SecurityScan(
            scanner_type="bandit",
            status=ScanLifecycle.COMPLETED_WITH_FINDINGS.value,
            initiated_by_user_id=analyst.id,
        )
        db.session.add(scan)
        db.session.flush()

        f1 = NormalizedFinding(
            scan_id=scan.id,
            scanner_name="bandit",
            tool_finding_id="B608",
            title="SQL Injection Vector",
            description="Raw string query formatting",
            severity=NormalizedSeverity.HIGH.value,
            target_component="app/routes/lab_vulnerable.py",
            fingerprint="fp1",
        )
        f2 = NormalizedFinding(
            scan_id=scan.id,
            scanner_name="pip_audit",
            tool_finding_id="PYSEC-001",
            title="Insecure Dependency",
            description="Outdated library vulnerability",
            severity=NormalizedSeverity.LOW.value,
            target_component="dummy==1.0",
            fingerprint="fp2",
        )
        db.session.add_all([f1, f2])
        db.session.commit()
        f1_id = f1.id

    auth.login(email="analyst_filter_test@vadl.local", password="Password123!@")

    # 1. Filter by severity=HIGH
    resp_high = client.get("/scans/findings?severity=HIGH")
    assert resp_high.status_code == 200
    html_high = resp_high.get_data(as_text=True)
    assert "SQL Injection Vector" in html_high
    assert "Insecure Dependency" not in html_high

    # 2. Filter by scanner=pip_audit
    resp_pip = client.get("/scans/findings?scanner=pip_audit")
    assert resp_pip.status_code == 200
    html_pip = resp_pip.get_data(as_text=True)
    assert "Insecure Dependency" in html_pip
    assert "SQL Injection Vector" not in html_pip

    # 3. View individual finding detail
    resp_detail = client.get(f"/scans/findings/{f1_id}")
    assert resp_detail.status_code == 200
    assert "Normalized Security Finding" in resp_detail.get_data(as_text=True)
