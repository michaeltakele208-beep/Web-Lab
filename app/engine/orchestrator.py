"""Assessment execution orchestrator and lifecycle engine."""

import json
import logging
import time
from datetime import UTC, datetime

from flask import current_app

from app.engine.adapters import get_adapter
from app.engine.evidence import build_evidence
from app.engine.semantics import (
    AssessmentStatus,
    AuditEventType,
    ErrorCategory,
    ResultOutcome,
)
from app.engine.target_guard import (
    AuthorizationError,
    recheck_target_authorization,
    validate_assessment_request,
)
from app.extensions import db
from app.models.assessment import Assessment, AssessmentAuditEvent, TestResult
from app.models.user import User

logger = logging.getLogger("vadl.engine.orchestrator")


class DuplicateAssessmentError(Exception):
    """Raised when an identical assessment request is detected in rapid succession."""

    pass


class AssessmentOrchestrator:
    """Manages the lifecycle, execution boundaries, and persistence of security assessments."""

    @classmethod
    def create_assessment(
        cls,
        user: User,
        target_id: int,
        scenario_ids: list[str],
        target_edition: str = "both",
        max_scenarios: int | None = None,
    ) -> Assessment:
        """Validate boundaries, check for duplicates, and register a new queued assessment."""
        if max_scenarios is None:
            max_scenarios = current_app.config.get("MAX_SCENARIOS_PER_ASSESSMENT", 10)

        # 1. Authorization and boundary validation
        target = validate_assessment_request(
            user=user,
            target_id=target_id,
            scenario_ids=scenario_ids,
            target_edition=target_edition,
            max_scenarios=max_scenarios,
        )

        # 2. Duplicate submission protection (check for identical active assessments created in the last 10s)
        serialized_scenarios = json.dumps(sorted(scenario_ids))
        recent_duplicate = (
            Assessment.query.filter_by(
                target_id=target_id,
                initiator_id=user.id,
                target_edition=target_edition,
            )
            .filter(
                Assessment.status.in_(
                    [AssessmentStatus.QUEUED.value, AssessmentStatus.RUNNING.value]
                )
            )
            .order_by(Assessment.created_at.desc())
            .first()
        )

        if (
            recent_duplicate
            and json.dumps(sorted(recent_duplicate.scenarios_list)) == serialized_scenarios
        ):
            raise DuplicateAssessmentError(
                "An identical assessment for this target and scenarios is currently in progress."
            )

        # 3. Instantiate and persist queued assessment
        assessment = Assessment(
            target_id=target.id,
            initiator_id=user.id,
            status=AssessmentStatus.QUEUED.value,
            selected_scenarios=serialized_scenarios,
            target_edition=target_edition,
            created_at=datetime.now(UTC),
        )
        db.session.add(assessment)
        db.session.flush()

        # 4. Record audit event
        audit = AssessmentAuditEvent(
            assessment_id=assessment.id,
            event_type=AuditEventType.REQUESTED.value,
            actor_id=user.id,
            details=f"Target: '{target.name}' ({target.base_url}) | Scenarios: {scenario_ids} | Edition: {target_edition}",
        )
        db.session.add(audit)
        db.session.commit()

        logger.info(f"Assessment #{assessment.id} successfully queued by user '{user.email}'.")
        return assessment

    @classmethod
    def execute_assessment(cls, assessment_id: int, client=None) -> Assessment:
        """Execute a queued assessment across selected scenarios with timeout and error protection."""
        assessment = db.session.get(Assessment, assessment_id)
        if not assessment:
            raise ValueError(f"Assessment #{assessment_id} not found.")

        # Ignore if cancelled before start
        if assessment.status == AssessmentStatus.CANCELLED.value:
            return assessment

        test_timeout = current_app.config.get("TEST_TIMEOUT_SECONDS", 5)
        max_duration = current_app.config.get("MAX_ASSESSMENT_DURATION_SECONDS", 60)
        max_evidence = current_app.config.get("MAX_EVIDENCE_BYTES", 4096)

        # Transition status to RUNNING
        assessment.status = AssessmentStatus.RUNNING.value
        assessment.started_at = datetime.now(UTC)

        audit_start = AssessmentAuditEvent(
            assessment_id=assessment.id,
            event_type=AuditEventType.STARTED.value,
            actor_id=assessment.initiator_id,
            details=f"Execution started for assessment #{assessment.id}.",
        )
        db.session.add(audit_start)
        db.session.commit()

        start_monotonic = time.monotonic()

        # In-process Flask test client if not provided
        if client is None:
            client = current_app.test_client()

        try:
            # 1. Re-verify target authorization immediately before execution
            is_authorized, auth_msg = recheck_target_authorization(assessment.target_id)
            if not is_authorized:
                assessment.status = AssessmentStatus.FAILED.value
                assessment.error_message = auth_msg
                assessment.completed_at = datetime.now(UTC)

                # Record ERROR result indicating target became unauthorized
                err_result = TestResult(
                    assessment_id=assessment.id,
                    scenario_id="GENERAL-AUTH",
                    test_identifier=f"PRECHECK_{int(time.time())}",
                    target_edition=assessment.target_edition,
                    outcome=ResultOutcome.ERROR.value,
                    error_category=ErrorCategory.TARGET_DISABLED.value,
                    evidence=build_evidence(
                        scenario_id="GENERAL-AUTH",
                        test_identifier="TARGET_AUTHORIZATION_PRECHECK",
                        target_edition=assessment.target_edition,
                        request_method="PRECHECK",
                        request_url=assessment.target.base_url if assessment.target else "N/A",
                        expected_behavior="Authorized target status",
                        observed_behavior=auth_msg,
                        rationale="Target was disabled or revoked prior to execution.",
                        max_bytes=max_evidence,
                    ),
                    started_at=datetime.now(UTC),
                    completed_at=datetime.now(UTC),
                    duration_ms=0,
                )
                db.session.add(err_result)
                assessment.total_tests = 1
                assessment.error_count = 1

                audit_fail = AssessmentAuditEvent(
                    assessment_id=assessment.id,
                    event_type=AuditEventType.FAILED.value,
                    actor_id=assessment.initiator_id,
                    details=f"Execution aborted: {auth_msg}",
                )
                db.session.add(audit_fail)
                db.session.commit()
                return assessment

            # 2. Determine target editions to execute
            editions_to_test = []
            if assessment.target_edition in ("vulnerable", "both"):
                editions_to_test.append("vulnerable")
            if assessment.target_edition in ("secure", "both"):
                editions_to_test.append("secure")

            # 3. Execute scenario adapters
            for scenario_id in assessment.scenarios_list:
                # Check overall assessment runtime duration limit
                if (time.monotonic() - start_monotonic) > max_duration:
                    logger.warning(
                        f"Assessment #{assessment.id} exceeded maximum duration of {max_duration}s."
                    )
                    timeout_res = TestResult(
                        assessment_id=assessment.id,
                        scenario_id=scenario_id,
                        test_identifier=f"TIMEOUT_{scenario_id}",
                        target_edition="both",
                        outcome=ResultOutcome.ERROR.value,
                        error_category=ErrorCategory.TIMEOUT.value,
                        evidence="Execution terminated: assessment exceeded total duration limit.",
                        started_at=datetime.now(UTC),
                        completed_at=datetime.now(UTC),
                        duration_ms=0,
                    )
                    db.session.add(timeout_res)
                    assessment.total_tests += 1
                    assessment.error_count += 1
                    break

                adapter = get_adapter(scenario_id)
                if not adapter:
                    logger.error(f"No adapter registered for scenario '{scenario_id}'.")
                    unsupported_res = TestResult(
                        assessment_id=assessment.id,
                        scenario_id=scenario_id,
                        test_identifier=f"UNSUPPORTED_{scenario_id}",
                        target_edition="both",
                        outcome=ResultOutcome.ERROR.value,
                        error_category=ErrorCategory.EXECUTION_FAULT.value,
                        evidence=f"No scenario adapter implemented for ID '{scenario_id}'.",
                        started_at=datetime.now(UTC),
                        completed_at=datetime.now(UTC),
                        duration_ms=0,
                    )
                    db.session.add(unsupported_res)
                    assessment.total_tests += 1
                    assessment.error_count += 1
                    continue

                for edition in editions_to_test:
                    result_payload = adapter.execute(
                        target=assessment.target,
                        edition=edition,
                        client=client,
                        timeout_seconds=test_timeout,
                        max_evidence_bytes=max_evidence,
                    )

                    test_record = TestResult(
                        assessment_id=assessment.id,
                        scenario_id=result_payload.scenario_id,
                        test_identifier=result_payload.test_identifier,
                        target_edition=result_payload.target_edition,
                        outcome=result_payload.outcome.value,
                        error_category=result_payload.error_category.value
                        if result_payload.error_category
                        else None,
                        evidence=result_payload.evidence,
                        started_at=result_payload.started_at,
                        completed_at=result_payload.completed_at,
                        duration_ms=result_payload.duration_ms,
                    )
                    db.session.add(test_record)

                    # Update aggregate counters
                    assessment.total_tests += 1
                    if result_payload.outcome == ResultOutcome.SECURITY_CHECK_PASSED:
                        assessment.passed_checks += 1
                    elif result_payload.outcome == ResultOutcome.VULNERABILITY_CONFIRMED:
                        assessment.confirmed_vulnerabilities += 1
                    elif result_payload.outcome == ResultOutcome.VULNERABILITY_NOT_REPRODUCED:
                        assessment.not_reproduced += 1
                    elif result_payload.outcome == ResultOutcome.ERROR:
                        assessment.error_count += 1

            # 4. Finalize status
            assessment.completed_at = datetime.now(UTC)
            if assessment.error_count > 0:
                assessment.status = AssessmentStatus.COMPLETED_WITH_ERRORS.value
            else:
                assessment.status = AssessmentStatus.COMPLETED.value

            audit_done = AssessmentAuditEvent(
                assessment_id=assessment.id,
                event_type=AuditEventType.COMPLETED.value,
                actor_id=assessment.initiator_id,
                details=(
                    f"Assessment finished with status '{assessment.status}'. "
                    f"Total: {assessment.total_tests}, Confirmed Vulns: {assessment.confirmed_vulnerabilities}, "
                    f"Passed Checks: {assessment.passed_checks}, Errors: {assessment.error_count}"
                ),
            )
            db.session.add(audit_done)
            db.session.commit()

        except Exception as exc:
            # Safe failure guarantee: never leave assessment permanently in RUNNING
            logger.exception(f"Fatal error during assessment #{assessment.id} execution: {exc}")
            db.session.rollback()

            assessment = db.session.get(Assessment, assessment_id)
            if assessment:
                assessment.status = AssessmentStatus.FAILED.value
                assessment.error_message = f"Internal execution failure: {str(exc)[:200]}"
                assessment.completed_at = datetime.now(UTC)

                audit_err = AssessmentAuditEvent(
                    assessment_id=assessment.id,
                    event_type=AuditEventType.FAILED.value,
                    actor_id=assessment.initiator_id,
                    details=f"Fatal exception during assessment: {str(exc)[:200]}",
                )
                db.session.add(audit_err)
                db.session.commit()

        return assessment

    @classmethod
    def cancel_assessment(cls, assessment_id: int, user: User) -> Assessment:
        """Cancel a queued or running assessment."""
        assessment = db.session.get(Assessment, assessment_id)
        if not assessment:
            raise ValueError(f"Assessment #{assessment_id} not found.")

        # Enforce permissions (initiator or admin)
        if user.id != assessment.initiator_id and user.role != "admin":
            raise AuthorizationError(
                "Only the assessment initiator or an administrator may cancel this assessment."
            )

        if assessment.status not in (AssessmentStatus.QUEUED.value, AssessmentStatus.RUNNING.value):
            raise ValueError(
                f"Assessment #{assessment_id} is in '{assessment.status}' status and cannot be cancelled."
            )

        assessment.status = AssessmentStatus.CANCELLED.value
        assessment.completed_at = datetime.now(UTC)

        audit = AssessmentAuditEvent(
            assessment_id=assessment.id,
            event_type=AuditEventType.CANCELLED.value,
            actor_id=user.id,
            details=f"Assessment #{assessment.id} was cancelled by '{user.email}'.",
        )
        db.session.add(audit)
        db.session.commit()
        return assessment
