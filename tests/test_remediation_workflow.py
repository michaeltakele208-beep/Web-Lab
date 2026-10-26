"""Automated tests for Phase 5 defensive remediation workflow and automated verification."""

import json

import pytest

from app.engine.comparison import ComparisonService
from app.engine.semantics import (
    AssessmentStatus,
    AuditEventType,
    RemediationStatus,
    ResultOutcome,
    VerificationOutcome,
)
from app.engine.verification import VerificationService
from app.extensions import db
from app.models.assessment import Assessment, TestResult
from app.models.lab import LabTarget
from app.models.remediation import Remediation, RemediationAuditEvent
from app.models.user import Role


@pytest.fixture
def target_and_analyst(app, auth):
    """Fixture providing authorized lab target and analyst user."""
    with app.app_context():
        target = LabTarget.query.filter_by(base_url="http://127.0.0.1:5000/lab").first()
        if not target:
            target = LabTarget(
                name="Remediation Local Target",
                base_url="http://127.0.0.1:5000/lab",
                environment_id="testing",
                is_authorized=True,
            )
            db.session.add(target)
            db.session.commit()
        target_id = target.id

        analyst = auth.create_user(
            email="remediation_analyst@vadl.local",
            password="Password123!@",
            display_name="Remediation Analyst",
            role=Role.SECURITY_ANALYST,
        )
        analyst_id = analyst.id

    return target_id, analyst_id


def test_remediation_anonymous_redirect(client):
    """Verify anonymous access to remediations console redirects to login."""
    resp = client.get("/remediations")
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


def test_remediation_ordinary_user_forbidden(client, auth):
    """Verify ordinary users receive HTTP 403 Forbidden on remediations blueprint."""
    auth.create_user(email="regular_user@vadl.local", password="Password123!@", role=Role.USER)
    auth.login(email="regular_user@vadl.local", password="Password123!@")
    resp_user = client.get("/remediations")
    assert resp_user.status_code == 403


def test_remediation_analyst_authorized(client, auth):
    """Verify security analyst receives HTTP 200 OK on remediations console."""
    auth.create_user(
        email="analyst_user@vadl.local", password="Password123!@", role=Role.SECURITY_ANALYST
    )
    auth.login(email="analyst_user@vadl.local", password="Password123!@")
    resp_analyst = client.get("/remediations")
    assert resp_analyst.status_code == 200
    assert "Remediation &amp; Defense Verification" in resp_analyst.get_data(as_text=True)


def test_remediation_creation_and_audit(app, target_and_analyst):
    """Verify remediation creation initializes OPEN status and records audit event."""
    target_id, analyst_id = target_and_analyst

    with app.app_context():
        analyst = db.session.get(auth_user_model(), analyst_id)

        remediation = Remediation(
            scenario_id="VADL-SQLI-001",
            title="Fix SQLi in product category filter",
            description="Parameterize category filter queries",
            remediation_details="Replace raw string formatting with SQLAlchemy parameter bindings",
            status=RemediationStatus.OPEN.value,
            verification_status=VerificationOutcome.UNVERIFIED.value,
            created_by_user_id=analyst.id,
        )
        db.session.add(remediation)
        db.session.flush()

        audit = RemediationAuditEvent(
            remediation_id=remediation.id,
            event_type=AuditEventType.REMEDIATION_CREATED.value,
            actor_id=analyst.id,
            old_status=None,
            new_status=RemediationStatus.OPEN.value,
            details="Remediation created",
        )
        db.session.add(audit)
        db.session.commit()

        # Assertions
        saved = db.session.get(Remediation, remediation.id)
        assert saved is not None
        assert saved.status == RemediationStatus.OPEN.value
        assert saved.verification_status == VerificationOutcome.UNVERIFIED.value
        assert saved.evidence_sha256 is None
        assert len(saved.audit_events) == 1
        assert saved.audit_events[0].event_type == AuditEventType.REMEDIATION_CREATED.value


def test_prohibit_manual_transition_to_verified(app, target_and_analyst):
    """Verify manual transitions to VERIFIED are strictly rejected with ValueError."""
    target_id, analyst_id = target_and_analyst

    with app.app_context():
        analyst = db.session.get(auth_user_model(), analyst_id)

        remediation = Remediation(
            scenario_id="VADL-SQLI-001",
            title="Manual verification attempt",
            status=RemediationStatus.IN_PROGRESS.value,
            created_by_user_id=analyst.id,
        )
        db.session.add(remediation)
        db.session.commit()
        remediation_id = remediation.id

        # Attempt manual transition to VERIFIED
        with pytest.raises(ValueError, match="prohibited"):
            VerificationService.update_workflow_status(
                remediation_id=remediation_id,
                new_status=RemediationStatus.VERIFIED.value,
                actor=analyst,
                note="Attempting to mark fixed manually",
            )

        # Confirm status remains unchanged
        reloaded = db.session.get(Remediation, remediation_id)
        assert reloaded.status == RemediationStatus.IN_PROGRESS.value


def test_valid_manual_workflow_transitions(app, target_and_analyst):
    """Verify allowed manual transitions (OPEN -> IN_PROGRESS -> READY_FOR_VERIFICATION)."""
    target_id, analyst_id = target_and_analyst

    with app.app_context():
        analyst = db.session.get(auth_user_model(), analyst_id)

        remediation = Remediation(
            scenario_id="VADL-XSS-001",
            title="XSS Remediation Track",
            status=RemediationStatus.OPEN.value,
            created_by_user_id=analyst.id,
        )
        db.session.add(remediation)
        db.session.commit()
        remediation_id = remediation.id

        # 1. OPEN -> IN_PROGRESS
        r1 = VerificationService.update_workflow_status(
            remediation_id=remediation_id,
            new_status=RemediationStatus.IN_PROGRESS.value,
            actor=analyst,
            note="Started defensive refactor",
        )
        assert r1.status == RemediationStatus.IN_PROGRESS.value

        # 2. IN_PROGRESS -> READY_FOR_VERIFICATION
        r2 = VerificationService.update_workflow_status(
            remediation_id=remediation_id,
            new_status=RemediationStatus.READY_FOR_VERIFICATION.value,
            actor=analyst,
            note="Escaping implemented, ready for automated tests",
        )
        assert r2.status == RemediationStatus.READY_FOR_VERIFICATION.value

        # Verify audit events recorded
        events = (
            RemediationAuditEvent.query.filter_by(remediation_id=remediation_id)
            .order_by(RemediationAuditEvent.id.asc())
            .all()
        )
        assert len(events) == 2
        assert events[0].old_status == RemediationStatus.OPEN.value
        assert events[0].new_status == RemediationStatus.IN_PROGRESS.value
        assert events[1].old_status == RemediationStatus.IN_PROGRESS.value
        assert events[1].new_status == RemediationStatus.READY_FOR_VERIFICATION.value


def test_automated_verification_sqli(app, target_and_analyst, lab_seed):
    """Verify automated defensive verification for SQL injection scenario (VADL-SQLI-001)."""
    target_id, analyst_id = target_and_analyst

    with app.app_context():
        analyst = db.session.get(auth_user_model(), analyst_id)

        remediation = Remediation(
            scenario_id="VADL-SQLI-001",
            title="SQLi Remediation",
            status=RemediationStatus.READY_FOR_VERIFICATION.value,
            created_by_user_id=analyst.id,
        )
        db.session.add(remediation)
        db.session.commit()
        remediation_id = remediation.id

        # Run verification
        updated_rem, outcome, evidence = VerificationService.verify_remediation(
            remediation_id=remediation_id,
            actor=analyst,
            target_id=target_id,
        )

        assert outcome == VerificationOutcome.VERIFIED
        assert updated_rem.status == RemediationStatus.VERIFIED.value
        assert updated_rem.verification_status == VerificationOutcome.VERIFIED.value
        assert updated_rem.evidence_sha256 is not None
        assert len(updated_rem.evidence_sha256) == 64  # SHA-256 hex digest length
        assert updated_rem.verification_result_id is not None
        assert updated_rem.verified_at is not None

        # Verify regression check details in evidence
        assert "SQLI_REGRESSION_LEGITIMATE_SEARCH" in evidence
        assert "Defensive parameterization" in evidence


def test_automated_verification_xss(app, target_and_analyst):
    """Verify automated defensive verification for XSS scenario (VADL-XSS-001)."""
    target_id, analyst_id = target_and_analyst

    with app.app_context():
        analyst = db.session.get(auth_user_model(), analyst_id)

        remediation = Remediation(
            scenario_id="VADL-XSS-001",
            title="XSS Auto-Escaping Remediation",
            status=RemediationStatus.READY_FOR_VERIFICATION.value,
            created_by_user_id=analyst.id,
        )
        db.session.add(remediation)
        db.session.commit()
        remediation_id = remediation.id

        updated_rem, outcome, evidence = VerificationService.verify_remediation(
            remediation_id=remediation_id,
            actor=analyst,
            target_id=target_id,
        )

        assert outcome == VerificationOutcome.VERIFIED
        assert updated_rem.status == RemediationStatus.VERIFIED.value
        assert "XSS_REGRESSION_PLAIN_TEXT" in evidence
        assert "Auto-escaping preserves legitimate" in evidence


def test_automated_verification_idor(app, target_and_analyst, lab_seed):
    """Verify automated defensive verification for IDOR scenario (VADL-AC-001)."""
    target_id, analyst_id = target_and_analyst

    with app.app_context():
        analyst = db.session.get(auth_user_model(), analyst_id)

        remediation = Remediation(
            scenario_id="VADL-AC-001",
            title="Broken Access Control Remediation",
            status=RemediationStatus.READY_FOR_VERIFICATION.value,
            created_by_user_id=analyst.id,
        )
        db.session.add(remediation)
        db.session.commit()
        remediation_id = remediation.id

        updated_rem, outcome, evidence = VerificationService.verify_remediation(
            remediation_id=remediation_id,
            actor=analyst,
            target_id=target_id,
        )

        assert outcome == VerificationOutcome.VERIFIED
        assert updated_rem.status == RemediationStatus.VERIFIED.value
        assert "IDOR_REGRESSION_LEGITIMATE_OWNER_ACCESS" in evidence
        assert "Ownership boundary enforced" in evidence


def test_automated_verification_security_headers(app, target_and_analyst):
    """Verify automated defensive verification for HTTP headers scenario (VADL-HEADERS-001)."""
    target_id, analyst_id = target_and_analyst

    with app.app_context():
        analyst = db.session.get(auth_user_model(), analyst_id)

        remediation = Remediation(
            scenario_id="VADL-HEADERS-001",
            title="Security Headers Remediation",
            status=RemediationStatus.READY_FOR_VERIFICATION.value,
            created_by_user_id=analyst.id,
        )
        db.session.add(remediation)
        db.session.commit()
        remediation_id = remediation.id

        updated_rem, outcome, evidence = VerificationService.verify_remediation(
            remediation_id=remediation_id,
            actor=analyst,
            target_id=target_id,
        )

        assert outcome == VerificationOutcome.VERIFIED
        assert updated_rem.status == RemediationStatus.VERIFIED.value
        assert "HEADERS_REGRESSION_CONTENT_TYPE_PRESERVED" in evidence
        assert "Content-Security-Policy" in evidence


def test_comparison_service_linked_finding(app, target_and_analyst, lab_seed):
    """Verify ComparisonService produces structured before-and-after diff linking vulnerable finding to verification."""
    target_id, analyst_id = target_and_analyst

    with app.app_context():
        analyst = db.session.get(auth_user_model(), analyst_id)

        # 1. Create a simulated offensive assessment and vulnerable finding
        assessment = Assessment(
            target_id=target_id,
            initiator_id=analyst.id,
            target_edition="vulnerable",
            selected_scenarios=json.dumps(["VADL-SQLI-001"]),
            status=AssessmentStatus.COMPLETED.value,
        )
        db.session.add(assessment)
        db.session.flush()

        vulnerable_finding = TestResult(
            assessment_id=assessment.id,
            scenario_id="VADL-SQLI-001",
            test_identifier="OFFENSIVE_SQLI_TEST_001",
            target_edition="vulnerable",
            outcome=ResultOutcome.VULNERABILITY_CONFIRMED.value,
            evidence="Extracted CONFIDENTIAL_LAB_FLAG via SQL injection",
        )
        db.session.add(vulnerable_finding)
        db.session.commit()

        # 2. Create remediation linked to this finding
        remediation = Remediation(
            scenario_id="VADL-SQLI-001",
            title="SQLi Remediation with Finding Link",
            finding_result_id=vulnerable_finding.id,
            original_assessment_id=assessment.id,
            status=RemediationStatus.READY_FOR_VERIFICATION.value,
            created_by_user_id=analyst.id,
        )
        db.session.add(remediation)
        db.session.commit()

        # 3. Run verification
        updated_rem, outcome, evidence = VerificationService.verify_remediation(
            remediation_id=remediation.id,
            actor=analyst,
            target_id=target_id,
        )
        assert outcome == VerificationOutcome.VERIFIED

        # 4. Generate comparison diff
        comparison = ComparisonService.compare_remediation(updated_rem)

        assert comparison["scenario_id"] == "VADL-SQLI-001"
        assert comparison["is_compatible"] is True
        assert comparison["remediation_confirmed"] is True
        assert comparison["delta_summary"] == "Vulnerability Successfully Remediated"

        # Check before / after structures
        assert comparison["before"]["result_id"] == vulnerable_finding.id
        assert comparison["before"]["outcome"] == ResultOutcome.VULNERABILITY_CONFIRMED.value
        assert comparison["before"]["edition"] == "vulnerable"

        assert comparison["after"]["result_id"] == updated_rem.verification_result_id
        assert comparison["after"]["outcome"] == ResultOutcome.SECURITY_CHECK_PASSED.value
        assert comparison["after"]["edition"] == "secure"
        assert comparison["after"]["evidence_sha256"] == updated_rem.evidence_sha256


def test_remediation_web_and_api_workflow(client, auth, lab_seed):
    """Verify web forms and JSON API endpoints for remediation management."""
    # Create target and analyst
    target = LabTarget.query.filter_by(base_url="http://127.0.0.1:5000/lab").first()
    if not target:
        target = LabTarget(
            name="API Test Target",
            base_url="http://127.0.0.1:5000/lab",
            environment_id="testing",
            is_authorized=True,
        )
        db.session.add(target)
        db.session.commit()

    analyst = auth.create_user(
        email="api_analyst@vadl.local",
        password="Password123!@",
        display_name="API Analyst",
        role=Role.SECURITY_ANALYST,
    )
    auth.login(email="api_analyst@vadl.local", password="Password123!@")
    csrf_token = auth.get_csrf_token("/remediations")

    # 1. Create remediation via JSON API
    resp_create = client.post(
        "/remediations",
        json={
            "scenario_id": "VADL-SQLI-001",
            "title": "API Test Remediation",
            "description": "Fixing SQL injection via API test",
            "remediation_details": "Using ORM queries",
            "assigned_user_id": analyst.id,
        },
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-CSRF-Token": csrf_token,
        },
    )
    assert resp_create.status_code == 201
    created_data = resp_create.get_json()
    rem_id = created_data["id"]
    assert created_data["status"] == "OPEN"

    # 2. Update status via JSON API to READY_FOR_VERIFICATION
    resp_status = client.post(
        f"/remediations/{rem_id}/status",
        json={"status": "READY_FOR_VERIFICATION", "note": "Ready for automated test run"},
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-CSRF-Token": csrf_token,
        },
    )
    assert resp_status.status_code == 200
    assert resp_status.get_json()["status"] == "READY_FOR_VERIFICATION"

    # 3. Prohibit manual VERIFIED via JSON API
    resp_manual = client.post(
        f"/remediations/{rem_id}/status",
        json={"status": "VERIFIED", "note": "Hacking status"},
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-CSRF-Token": csrf_token,
        },
    )
    assert resp_manual.status_code == 400
    assert "prohibited" in resp_manual.get_json()["error"]

    # 4. Trigger automated verification via JSON API
    resp_verify = client.post(
        f"/remediations/{rem_id}/verify",
        json={"target_id": target.id},
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-CSRF-Token": csrf_token,
        },
    )
    assert resp_verify.status_code == 200
    verify_data = resp_verify.get_json()
    assert verify_data["verification_outcome"] == "VERIFIED"
    assert verify_data["remediation"]["status"] == "VERIFIED"
    assert len(verify_data["evidence_sha256"]) == 64

    # 5. Fetch comparison JSON API
    resp_compare = client.get(
        f"/remediations/{rem_id}/compare",
        headers={"Accept": "application/json"},
    )
    assert resp_compare.status_code == 200
    assert resp_compare.get_json()["scenario_id"] == "VADL-SQLI-001"

    # 6. Fetch comparison HTML view
    resp_html = client.get(f"/remediations/{rem_id}/compare")
    assert resp_html.status_code == 200
    assert "Before &amp; After Remediation Diff" in resp_html.get_data(as_text=True)


def auth_user_model():
    """Helper returning User model class."""
    from app.models.user import User

    return User
