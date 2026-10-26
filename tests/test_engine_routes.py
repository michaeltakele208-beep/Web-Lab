"""Automated tests for Phase 4 assessment routes, UI templates, and JSON API."""

from app.extensions import db
from app.models.assessment import Assessment
from app.models.lab import LabTarget
from app.models.user import Role


def test_assessments_console_anonymous_redirect(client):
    """Verify anonymous access to assessment dashboard redirects to login."""
    resp = client.get("/assessments")
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


def test_assessments_console_ordinary_user_forbidden(client, auth):
    """Verify ordinary user receives HTTP 403 Forbidden on assessment console."""
    auth.create_user(email="user_route@vadl.local", password="Password123!@", role=Role.USER)
    auth.login(email="user_route@vadl.local", password="Password123!@")
    resp_user = client.get("/assessments")
    assert resp_user.status_code == 403


def test_assessments_console_analyst_authorized(client, auth):
    """Verify security analyst receives HTTP 200 OK on assessment console."""
    auth.create_user(
        email="analyst_route@vadl.local", password="Password123!@", role=Role.SECURITY_ANALYST
    )
    auth.login(email="analyst_route@vadl.local", password="Password123!@")
    resp_analyst = client.get("/assessments")
    assert resp_analyst.status_code == 200
    assert "Security Assessment Console" in resp_analyst.get_data(as_text=True)
    assert "Launch Offensive Security Assessment" in resp_analyst.get_data(as_text=True)


def test_run_assessment_via_web_form(client, auth, lab_seed):
    """Verify triggering an assessment via browser form submission."""
    # Ensure authorized target exists
    target = LabTarget.query.filter_by(base_url="http://127.0.0.1:5000/lab").first()
    if not target:
        target = LabTarget(
            name="Route Test Sandbox",
            base_url="http://127.0.0.1:5000/lab",
            environment_id="testing",
            is_authorized=True,
        )
        db.session.add(target)
        db.session.commit()

    auth.create_user(
        email="analyst_form@vadl.local", password="Password123!@", role=Role.SECURITY_ANALYST
    )
    auth.login(email="analyst_form@vadl.local", password="Password123!@")

    csrf_token = auth.get_csrf_token("/assessments")

    # Post form to run assessment
    resp = client.post(
        "/assessments/run",
        data={
            "target_id": target.id,
            "target_edition": "both",
            "scenarios": ["VADL-SQLI-001"],
            "csrf_token": csrf_token,
        },
        follow_redirects=True,
    )
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert "Assessment Run #" in html
    assert "VULNERABILITY CONFIRMED" in html
    assert "SECURITY CHECK PASSED" in html


def test_run_assessment_via_json_api(client, auth, lab_seed):
    """Verify triggering an assessment via programmatic JSON API."""
    target = LabTarget.query.filter_by(base_url="http://127.0.0.1:5000/lab").first()
    if not target:
        target = LabTarget(
            name="API Test Sandbox",
            base_url="http://127.0.0.1:5000/lab",
            environment_id="testing",
            is_authorized=True,
        )
        db.session.add(target)
        db.session.commit()

    auth.create_user(
        email="analyst_api@vadl.local", password="Password123!@", role=Role.SECURITY_ANALYST
    )
    auth.login(email="analyst_api@vadl.local", password="Password123!@")

    csrf_token = auth.get_csrf_token("/assessments")

    resp = client.post(
        "/assessments/run",
        json={
            "target_id": target.id,
            "target_edition": "secure",
            "scenarios": ["VADL-HEADERS-001"],
        },
        headers={
            "Accept": "application/json",
            "X-CSRF-Token": csrf_token,
        },
    )
    assert resp.status_code == 201
    data = resp.get_json()
    assert "id" in data
    assert data["status"] == "completed"
    assert data["passed_checks"] >= 1


def test_assessment_detail_and_result_inspection(client, auth, lab_seed):
    """Verify navigating to assessment detail view and inspecting forensic evidence."""
    target = LabTarget.query.filter_by(base_url="http://127.0.0.1:5000/lab").first()
    if not target:
        target = LabTarget(
            name="Detail Sandbox",
            base_url="http://127.0.0.1:5000/lab",
            environment_id="testing",
            is_authorized=True,
        )
        db.session.add(target)
        db.session.commit()

    auth.create_user(
        email="analyst_detail@vadl.local", password="Password123!@", role=Role.SECURITY_ANALYST
    )
    auth.login(email="analyst_detail@vadl.local", password="Password123!@")

    csrf_token = auth.get_csrf_token("/assessments")
    run_resp = client.post(
        "/assessments/run",
        data={
            "target_id": target.id,
            "target_edition": "vulnerable",
            "scenarios": ["VADL-SQLI-001"],
            "csrf_token": csrf_token,
        },
    )
    assert run_resp.status_code == 302
    assessment_id = int(run_resp.headers["Location"].split("/")[-1])

    # 1. View Assessment Detail
    detail_resp = client.get(f"/assessments/{assessment_id}")
    assert detail_resp.status_code == 200
    html = detail_resp.get_data(as_text=True)
    assert f"Assessment Run #{assessment_id}" in html

    assessment = db.session.get(Assessment, assessment_id)
    assert assessment.results
    first_result = assessment.results[0]

    # 2. View Individual Result Evidence
    result_resp = client.get(f"/assessments/{assessment_id}/results/{first_result.id}")
    assert result_resp.status_code == 200
    res_html = result_resp.get_data(as_text=True)
    assert "Sanitized Forensic Evidence" in res_html
    assert first_result.test_identifier in res_html


def test_assessment_history_pagination(client, auth):
    """Verify assessment history view renders correctly with pagination."""
    auth.create_user(
        email="analyst_hist@vadl.local", password="Password123!@", role=Role.SECURITY_ANALYST
    )
    auth.login(email="analyst_hist@vadl.local", password="Password123!@")

    resp = client.get("/assessments/history")
    assert resp.status_code == 200
    assert "Assessment Execution History" in resp.get_data(as_text=True)


def test_run_assessment_rejects_missing_csrf_token(client, auth):
    """Verify state-changing assessment runs reject requests without CSRF token."""
    target = LabTarget.query.filter_by(base_url="http://127.0.0.1:5000/lab").first()
    if not target:
        target = LabTarget(
            name="CSRF Sandbox",
            base_url="http://127.0.0.1:5000/lab",
            environment_id="testing",
            is_authorized=True,
        )
        db.session.add(target)
        db.session.commit()

    auth.create_user(
        email="analyst_csrf@vadl.local", password="Password123!@", role=Role.SECURITY_ANALYST
    )
    auth.login(email="analyst_csrf@vadl.local", password="Password123!@")

    # Missing token -> 400 Bad Request
    resp = client.post(
        "/assessments/run",
        data={
            "target_id": target.id,
            "target_edition": "both",
            "scenarios": ["VADL-SQLI-001"],
        },
    )
    assert resp.status_code == 400
