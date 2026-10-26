"""Automated tests for Phase 4 assessment orchestrator, lifecycle, and safety boundaries."""

import pytest

from app.engine.evidence import sanitize_text, truncate_evidence
from app.engine.orchestrator import AssessmentOrchestrator, DuplicateAssessmentError
from app.engine.semantics import AssessmentStatus, AuditEventType, ErrorCategory, ResultOutcome
from app.engine.target_guard import AuthorizationError
from app.extensions import db
from app.models.assessment import AssessmentAuditEvent, TestResult
from app.models.lab import LabTarget
from app.models.user import Role, User


@pytest.fixture
def analyst_user_id(app):
    """Fixture providing an authorized security analyst user ID."""
    with app.app_context():
        user = User.query.filter_by(email="analyst_orch@vadl.local").first()
        if not user:
            user = User(
                email="analyst_orch@vadl.local",
                display_name="Analyst Orchestrator",
                role=Role.SECURITY_ANALYST,
            )
            user.set_password("Password123!@")
            db.session.add(user)
            db.session.commit()
        return user.id


@pytest.fixture
def regular_user_id(app):
    """Fixture providing an ordinary unauthorized user ID."""
    with app.app_context():
        user = User.query.filter_by(email="regular_orch@vadl.local").first()
        if not user:
            user = User(
                email="regular_orch@vadl.local",
                display_name="Regular Orchestrator",
                role=Role.USER,
            )
            user.set_password("Password123!@")
            db.session.add(user)
            db.session.commit()
        return user.id


@pytest.fixture
def lab_target_id(app):
    """Fixture providing an authorized lab target ID."""
    with app.app_context():
        target = LabTarget.query.filter_by(base_url="http://127.0.0.1:5000/lab").first()
        if not target:
            target = LabTarget(
                name="Local Sandbox Target",
                base_url="http://127.0.0.1:5000/lab",
                environment_id="testing",
                is_authorized=True,
            )
            db.session.add(target)
            db.session.commit()
        return target.id


def test_assessment_lifecycle_success(app, client, analyst_user_id, lab_target_id, lab_seed):
    """Verify standard assessment lifecycle: queued -> running -> completed."""
    with app.app_context():
        user = db.session.get(User, analyst_user_id)
        assessment = AssessmentOrchestrator.create_assessment(
            user=user,
            target_id=lab_target_id,
            scenario_ids=["VADL-SQLI-001", "VADL-HEADERS-001"],
            target_edition="both",
        )
        assert assessment.status == AssessmentStatus.QUEUED.value
        assert assessment.total_tests == 0
        assessment_id = assessment.id

        # Check audit event for request
        req_audit = AssessmentAuditEvent.query.filter_by(
            assessment_id=assessment_id, event_type=AuditEventType.REQUESTED.value
        ).first()
        assert req_audit is not None

        # Execute assessment
        completed_assessment = AssessmentOrchestrator.execute_assessment(
            assessment_id, client=client
        )
        assert completed_assessment.status == AssessmentStatus.COMPLETED.value
        assert completed_assessment.total_tests == 4  # 2 scenarios x 2 editions
        assert completed_assessment.confirmed_vulnerabilities >= 2  # vulnerable editions confirmed
        assert completed_assessment.passed_checks >= 2  # secure editions passed
        assert completed_assessment.error_count == 0
        assert completed_assessment.completed_at is not None

        # Verify audit trail contains completion
        done_audit = AssessmentAuditEvent.query.filter_by(
            assessment_id=assessment_id, event_type=AuditEventType.COMPLETED.value
        ).first()
        assert done_audit is not None


def test_ordinary_user_cannot_initiate_assessment(app, regular_user_id, lab_target_id):
    """Verify ordinary users without security_analyst or admin roles are rejected."""
    with app.app_context():
        user = db.session.get(User, regular_user_id)
        with pytest.raises(AuthorizationError, match="not authorized to execute security testing"):
            AssessmentOrchestrator.create_assessment(
                user=user,
                target_id=lab_target_id,
                scenario_ids=["VADL-SQLI-001"],
            )

        # Verify auth_rejected audit event logged
        rejected_audit = AssessmentAuditEvent.query.filter_by(
            event_type=AuditEventType.AUTH_REJECTED.value, actor_id=regular_user_id
        ).first()
        assert rejected_audit is not None


def test_unauthorized_target_rejected(app, analyst_user_id):
    """Verify attempting to assess an unauthorized target raises AuthorizationError."""
    with app.app_context():
        user = db.session.get(User, analyst_user_id)
        unauth_target = LabTarget(
            name="Disabled Target",
            base_url="http://127.0.0.1:5001/lab",
            environment_id="testing",
            is_authorized=False,
        )
        db.session.add(unauth_target)
        db.session.commit()

        with pytest.raises(AuthorizationError, match="not currently authorized"):
            AssessmentOrchestrator.create_assessment(
                user=user,
                target_id=unauth_target.id,
                scenario_ids=["VADL-SQLI-001"],
            )


def test_target_disabled_while_queued_fails_safely(app, client, analyst_user_id, lab_target_id):
    """Verify safe handling if a target's authorization is revoked after queuing."""
    with app.app_context():
        user = db.session.get(User, analyst_user_id)
        assessment = AssessmentOrchestrator.create_assessment(
            user=user,
            target_id=lab_target_id,
            scenario_ids=["VADL-SQLI-001"],
        )

        # Simulate administrative revocation while job was queued
        target = db.session.get(LabTarget, lab_target_id)
        target.is_authorized = False
        db.session.commit()

        # Execute
        result = AssessmentOrchestrator.execute_assessment(assessment.id, client=client)
        assert result.status == AssessmentStatus.FAILED.value
        assert "revoked while queued" in result.error_message
        assert result.error_count == 1

        # Check recorded ERROR test result
        err_res = TestResult.query.filter_by(assessment_id=assessment.id).first()
        assert err_res is not None
        assert err_res.outcome == ResultOutcome.ERROR.value
        assert err_res.error_category == ErrorCategory.TARGET_DISABLED.value

        # Restore target authorization
        target.is_authorized = True
        db.session.commit()


def test_duplicate_assessment_submission_protection(app, analyst_user_id, lab_target_id):
    """Verify submitting identical requests in rapid succession raises DuplicateAssessmentError."""
    with app.app_context():
        user = db.session.get(User, analyst_user_id)
        AssessmentOrchestrator.create_assessment(
            user=user,
            target_id=lab_target_id,
            scenario_ids=["VADL-SQLI-001"],
        )

        with pytest.raises(DuplicateAssessmentError, match="identical assessment"):
            AssessmentOrchestrator.create_assessment(
                user=user,
                target_id=lab_target_id,
                scenario_ids=["VADL-SQLI-001"],
            )


def test_unregistered_scenario_rejected(app, analyst_user_id, lab_target_id):
    """Verify unknown or unallowlisted scenarios are rejected."""
    with app.app_context():
        user = db.session.get(User, analyst_user_id)
        with pytest.raises(AuthorizationError, match="not registered"):
            AssessmentOrchestrator.create_assessment(
                user=user,
                target_id=lab_target_id,
                scenario_ids=["MALICIOUS-CUSTOM-001"],
            )


def test_max_scenarios_limit_enforced(app, analyst_user_id, lab_target_id):
    """Verify requesting more than MAX_SCENARIOS_PER_ASSESSMENT is rejected."""
    with app.app_context():
        user = db.session.get(User, analyst_user_id)
        many_scenarios = ["VADL-SQLI-001"] * 15
        with pytest.raises(AuthorizationError, match="exceeding maximum limit"):
            AssessmentOrchestrator.create_assessment(
                user=user,
                target_id=lab_target_id,
                scenario_ids=many_scenarios,
                max_scenarios=5,
            )


def test_cancel_assessment(app, analyst_user_id, lab_target_id):
    """Verify cancelling an active or queued assessment."""
    with app.app_context():
        user = db.session.get(User, analyst_user_id)
        assessment = AssessmentOrchestrator.create_assessment(
            user=user,
            target_id=lab_target_id,
            scenario_ids=["VADL-SQLI-001"],
        )
        assert assessment.status == AssessmentStatus.QUEUED.value

        cancelled = AssessmentOrchestrator.cancel_assessment(assessment.id, user)
        assert cancelled.status == AssessmentStatus.CANCELLED.value

        # Verify audit event
        cancel_audit = AssessmentAuditEvent.query.filter_by(
            assessment_id=assessment.id, event_type=AuditEventType.CANCELLED.value
        ).first()
        assert cancel_audit is not None


def test_evidence_sanitization_and_truncation():
    """Verify evidence scrubbing removes secrets and truncates large payloads."""
    raw = "user credentials: password=SecretPass123!&csrf_token=aabbccdd1122&session=cookie_val"
    sanitized = sanitize_text(raw)
    assert "[REDACTED_PASSWORD]" in sanitized
    assert "SecretPass123!" not in sanitized
    assert "[REDACTED_CSRF_TOKEN]" in sanitized
    assert "[REDACTED_SESSION]" in sanitized

    # Test size truncation
    large_payload = "A" * 5000
    truncated = truncate_evidence(large_payload, max_bytes=100)
    assert len(truncated.encode("utf-8")) < 200
    assert "[TRUNCATED: Exceeded evidence size limit]" in truncated
