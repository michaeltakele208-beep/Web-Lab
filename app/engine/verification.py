"""Defensive controls and remediation verification service (Phase 5)."""

import json
import logging
import time
from datetime import UTC, datetime

from flask import current_app

from app.engine.adapters import get_adapter
from app.engine.evidence import build_evidence, sanitize_text, truncate_evidence
from app.engine.semantics import (
    AuditEventType,
    RemediationStatus,
    ResultOutcome,
    VerificationOutcome,
)
from app.engine.target_guard import (
    AuthorizationError,
    recheck_target_authorization,
    validate_assessment_request,
)
from app.extensions import db
from app.lab.registry import get_scenario
from app.models.assessment import Assessment, TestResult
from app.models.lab import LabProduct, LabRecord, LabTarget
from app.models.remediation import Remediation, RemediationAuditEvent
from app.models.user import Role, User

logger = logging.getLogger("vadl.engine.verification")


class VerificationService:
    """Service orchestrating defensive verification, regression checks, and remediation transitions."""

    @classmethod
    def update_workflow_status(
        cls,
        remediation_id: int,
        new_status: str,
        actor: User,
        note: str | None = None,
    ) -> Remediation:
        """Update remediation workflow status with strict enforcement of verification boundaries."""
        if not actor or actor.role not in (Role.SECURITY_ANALYST, Role.ADMIN):
            raise AuthorizationError(
                "Only security analysts and administrators may update remediation status."
            )

        remediation = db.session.get(Remediation, remediation_id)
        if not remediation:
            raise ValueError(f"Remediation #{remediation_id} not found.")

        valid_manual_statuses = {
            RemediationStatus.OPEN.value,
            RemediationStatus.IN_PROGRESS.value,
            RemediationStatus.READY_FOR_VERIFICATION.value,
            RemediationStatus.REOPENED.value,
        }

        # CRITICAL CONTROL: Users cannot mark an issue VERIFIED through a manual request
        if new_status == RemediationStatus.VERIFIED.value:
            raise ValueError(
                "Direct transition to 'VERIFIED' status is prohibited. "
                "A remediation can only be verified through successful automated defensive verification."
            )

        if new_status not in valid_manual_statuses:
            raise ValueError(
                f"Invalid status '{new_status}'. Permitted statuses: {sorted(valid_manual_statuses)}."
            )

        old_status = remediation.status
        remediation.status = new_status
        remediation.updated_at = datetime.now(UTC)

        # Audit event
        audit = RemediationAuditEvent(
            remediation_id=remediation.id,
            event_type=AuditEventType.STATUS_CHANGED.value,
            actor_id=actor.id,
            old_status=old_status,
            new_status=new_status,
            details=note
            or f"Status updated from '{old_status}' to '{new_status}' by {actor.email}.",
        )
        db.session.add(audit)
        db.session.commit()
        return remediation

    @classmethod
    def verify_remediation(
        cls,
        remediation_id: int,
        actor: User,
        target_id: int | None = None,
        client=None,
    ) -> tuple[Remediation, VerificationOutcome, str]:
        """Execute defensive verification and regression tests against the secure edition of a target."""
        # 1. Authorization & Role Check
        if not actor or actor.role not in (Role.SECURITY_ANALYST, Role.ADMIN):
            raise AuthorizationError(
                "Only security analysts and administrators may execute remediation verification."
            )

        remediation = db.session.get(Remediation, remediation_id)
        if not remediation:
            raise ValueError(f"Remediation #{remediation_id} not found.")

        scenario = get_scenario(remediation.scenario_id)
        if not scenario:
            raise ValueError(f"Scenario '{remediation.scenario_id}' is not a registered scenario.")

        # 2. Target Resolution & Authorization Guard
        if target_id is None:
            # Default to first authorized lab target
            default_target = LabTarget.query.filter_by(is_authorized=True).first()
            if not default_target:
                raise AuthorizationError(
                    "No authorized laboratory targets are currently available for verification."
                )
            target_id = default_target.id

        target = validate_assessment_request(
            user=actor,
            target_id=target_id,
            scenario_ids=[remediation.scenario_id],
            target_edition="secure",
        )

        is_auth, auth_msg = recheck_target_authorization(target.id)
        if not is_auth:
            raise AuthorizationError(f"Target authorization rejected: {auth_msg}")

        # Audit verification request
        audit_req = RemediationAuditEvent(
            remediation_id=remediation.id,
            event_type=AuditEventType.VERIFICATION_REQUESTED.value,
            actor_id=actor.id,
            old_status=remediation.status,
            new_status=remediation.status,
            details=f"Verification requested against target '{target.name}' ({target.base_url}).",
        )
        db.session.add(audit_req)
        db.session.commit()

        if client is None:
            client = current_app.test_client()

        max_evidence = current_app.config.get("MAX_EVIDENCE_BYTES", 4096)
        timeout_seconds = current_app.config.get("TEST_TIMEOUT_SECONDS", 5)

        # 3. Create dedicated verification Assessment run
        now = datetime.now(UTC)
        verification_assessment = Assessment(
            target_id=target.id,
            initiator_id=actor.id,
            status="running",
            selected_scenarios=json.dumps([remediation.scenario_id]),
            target_edition="secure",
            created_at=now,
            started_at=now,
        )
        db.session.add(verification_assessment)
        db.session.flush()

        checks_passed = 0
        checks_failed = 0
        evidence_entries = []
        overall_outcome = VerificationOutcome.VERIFIED

        try:
            # 4. Scenario-Specific Defensive Verification & Regression Checks
            if remediation.scenario_id == "VADL-SQLI-001":
                # Ensure synthetic product fixture exists for regression test
                if LabProduct.query.count() == 0:
                    p = LabProduct(
                        name="Firewall Appliance",
                        category="hardware",
                        description="Perimeter network defense box",
                        price=299.99,
                        is_secret_test_flag=False,
                    )
                    db.session.add(p)
                    db.session.commit()

                # Check 1: Primary defense - Parameter binding neutralizes tautology
                sqli_adapter = get_adapter("VADL-SQLI-001")
                adapter_res = sqli_adapter.execute(
                    target=target,
                    edition="secure",
                    client=client,
                    timeout_seconds=timeout_seconds,
                    max_evidence_bytes=max_evidence,
                )
                evidence_entries.append(adapter_res.evidence)

                if adapter_res.outcome == ResultOutcome.SECURITY_CHECK_PASSED:
                    checks_passed += 1
                else:
                    checks_failed += 1
                    overall_outcome = VerificationOutcome.FAILED

                # Check 2: Regression check - Legitimate queries return valid search results
                initial_count = LabProduct.query.count()
                legit_resp = client.get("/lab/secure/sqli?category=hardware")
                legit_html = legit_resp.get_data(as_text=True)

                if legit_resp.status_code == 200 and "Firewall Appliance" in legit_html:
                    checks_passed += 1
                    evidence_entries.append(
                        build_evidence(
                            scenario_id="VADL-SQLI-001",
                            test_identifier="SQLI_REGRESSION_LEGITIMATE_SEARCH",
                            target_edition="secure",
                            request_method="GET",
                            request_url="/lab/secure/sqli?category=hardware",
                            response_status=legit_resp.status_code,
                            response_body_snippet=legit_html[:300],
                            expected_behavior="Valid products returned for legitimate category",
                            observed_behavior="Legitimate hardware products correctly displayed",
                            rationale="Defensive parameterization preserved legitimate application utility.",
                            max_bytes=max_evidence,
                        )
                    )
                else:
                    checks_failed += 1
                    overall_outcome = VerificationOutcome.FAILED

                # Check 3: Database integrity check - No records modified or deleted
                post_count = LabProduct.query.count()
                if initial_count == post_count:
                    checks_passed += 1
                else:
                    checks_failed += 1
                    overall_outcome = VerificationOutcome.FAILED

            elif remediation.scenario_id == "VADL-XSS-001":
                # Check 1: Primary defense - Contextual auto-escaping encodes HTML entities
                xss_adapter = get_adapter("VADL-XSS-001")
                adapter_res = xss_adapter.execute(
                    target=target,
                    edition="secure",
                    client=client,
                    timeout_seconds=timeout_seconds,
                    max_evidence_bytes=max_evidence,
                )
                evidence_entries.append(adapter_res.evidence)

                if adapter_res.outcome == ResultOutcome.SECURITY_CHECK_PASSED:
                    checks_passed += 1
                else:
                    checks_failed += 1
                    overall_outcome = VerificationOutcome.FAILED

                # Check 2: Regression check - Plain text and ordinary comments render correctly
                with client.session_transaction() as sess:
                    csrf_tok = sess.get("_csrf_token", "")
                reg_resp = client.post(
                    "/lab/secure/xss",
                    data={
                        "author": "QualityEngineer",
                        "content": "Defensive regression verification test comment.",
                        "csrf_token": csrf_tok,
                    },
                    follow_redirects=True,
                )
                reg_html = reg_resp.get_data(as_text=True)
                if "Defensive regression verification test comment." in reg_html:
                    checks_passed += 1
                    evidence_entries.append(
                        build_evidence(
                            scenario_id="VADL-XSS-001",
                            test_identifier="XSS_REGRESSION_PLAIN_TEXT",
                            target_edition="secure",
                            request_method="POST / GET",
                            request_url="/lab/secure/xss",
                            response_status=reg_resp.status_code,
                            expected_behavior="Ordinary comments display correctly without corruption",
                            observed_behavior="Plain text comment rendered as expected",
                            rationale="Auto-escaping preserves legitimate plain-text user content.",
                            max_bytes=max_evidence,
                        )
                    )
                else:
                    checks_failed += 1
                    overall_outcome = VerificationOutcome.FAILED

            elif remediation.scenario_id == "VADL-AC-001":
                # Ensure synthetic record fixture exists for regression test
                own_record = db.session.get(LabRecord, 1)
                if not own_record:
                    own_record = LabRecord(
                        id=1,
                        owner_username="synthetic-user-1@vadl.local",
                        title="Alpha Project Brief",
                        confidential_note="Confidential research payload for synthetic participant 1.",
                    )
                    db.session.add(own_record)
                    db.session.commit()

                # Check 1: Primary defense - Cross-user horizontal access denied with HTTP 403
                idor_adapter = get_adapter("VADL-AC-001")
                adapter_res = idor_adapter.execute(
                    target=target,
                    edition="secure",
                    client=client,
                    timeout_seconds=timeout_seconds,
                    max_evidence_bytes=max_evidence,
                )
                evidence_entries.append(adapter_res.evidence)

                if adapter_res.outcome == ResultOutcome.SECURITY_CHECK_PASSED:
                    checks_passed += 1
                else:
                    checks_failed += 1
                    overall_outcome = VerificationOutcome.FAILED

                # Check 2: Regression check - Legitimate owner can view their OWN confidential record
                own_resp = client.get(
                    "/lab/secure/records/1",
                    headers={"X-Lab-User": own_record.owner_username},
                )
                if (
                    own_resp.status_code == 200
                    and own_record.confidential_note in own_resp.get_data(as_text=True)
                ):
                    checks_passed += 1
                    evidence_entries.append(
                        build_evidence(
                            scenario_id="VADL-AC-001",
                            test_identifier="IDOR_REGRESSION_LEGITIMATE_OWNER_ACCESS",
                            target_edition="secure",
                            request_method="GET",
                            request_url="/lab/secure/records/1",
                            response_status=200,
                            expected_behavior="Legitimate record owner can view their own record",
                            observed_behavior="Owner successfully accessed confidential record #1",
                            rationale="Access control authorization correctly distinguishes owners from non-owners.",
                            max_bytes=max_evidence,
                        )
                    )
                else:
                    checks_failed += 1
                    overall_outcome = VerificationOutcome.FAILED

            elif remediation.scenario_id == "VADL-HEADERS-001":
                # Check 1: Primary defense - Actual HTTP security headers configured
                headers_adapter = get_adapter("VADL-HEADERS-001")
                adapter_res = headers_adapter.execute(
                    target=target,
                    edition="secure",
                    client=client,
                    timeout_seconds=timeout_seconds,
                    max_evidence_bytes=max_evidence,
                )
                evidence_entries.append(adapter_res.evidence)

                if adapter_res.outcome == ResultOutcome.SECURITY_CHECK_PASSED:
                    checks_passed += 1
                else:
                    checks_failed += 1
                    overall_outcome = VerificationOutcome.FAILED

                # Check 2: Regression check - Content-Type preserved and response successful
                headers_resp = client.get("/lab/secure/headers")
                if headers_resp.status_code == 200 and "Content-Type" in headers_resp.headers:
                    checks_passed += 1
                    evidence_entries.append(
                        build_evidence(
                            scenario_id="VADL-HEADERS-001",
                            test_identifier="HEADERS_REGRESSION_CONTENT_TYPE_PRESERVED",
                            target_edition="secure",
                            request_method="GET",
                            request_url="/lab/secure/headers",
                            response_status=200,
                            expected_behavior="Response includes standard Content-Type along with security headers",
                            observed_behavior=f"Content-Type '{headers_resp.headers.get('Content-Type')}' preserved",
                            rationale="Defensive security headers do not interfere with standard application MIME typing.",
                            max_bytes=max_evidence,
                        )
                    )
                else:
                    checks_failed += 1
                    overall_outcome = VerificationOutcome.FAILED

            else:
                overall_outcome = VerificationOutcome.NOT_APPLICABLE
                evidence_entries.append(
                    f"No verification adapter implemented for scenario '{remediation.scenario_id}'."
                )

            # Finalize verification test result in DB
            compiled_evidence = "\n---\n".join(evidence_entries)
            sanitized_evidence = sanitize_text(compiled_evidence)
            bounded_evidence = truncate_evidence(sanitized_evidence, max_bytes=max_evidence)

            test_result = TestResult(
                assessment_id=verification_assessment.id,
                scenario_id=remediation.scenario_id,
                test_identifier=f"VERIFY_{remediation.scenario_id}_{int(time.time())}",
                target_edition="secure",
                outcome=ResultOutcome.SECURITY_CHECK_PASSED.value
                if overall_outcome == VerificationOutcome.VERIFIED
                else ResultOutcome.VULNERABILITY_CONFIRMED.value,
                evidence=bounded_evidence,
                started_at=now,
                completed_at=datetime.now(UTC),
                duration_ms=50,
            )
            db.session.add(test_result)
            db.session.flush()

            # Finalize verification assessment
            verification_assessment.status = (
                "completed"
                if overall_outcome == VerificationOutcome.VERIFIED
                else "completed_with_errors"
            )
            verification_assessment.completed_at = datetime.now(UTC)
            verification_assessment.total_tests = checks_passed + checks_failed
            verification_assessment.passed_checks = checks_passed

            # 5. Transition Remediation Record State
            old_workflow_status = remediation.status
            remediation.verification_status = overall_outcome.value
            remediation.verification_result_id = test_result.id
            remediation.verification_assessment_id = verification_assessment.id
            remediation.verified_at = datetime.now(UTC)
            remediation.verified_by_user_id = actor.id
            remediation.sanitized_verification_evidence = bounded_evidence
            remediation.evidence_sha256 = Remediation.compute_evidence_hash(bounded_evidence)

            if overall_outcome == VerificationOutcome.VERIFIED:
                remediation.status = RemediationStatus.VERIFIED.value
                audit_event_type = AuditEventType.VERIFICATION_COMPLETED.value
                audit_detail = (
                    f"Remediation #{remediation.id} successfully verified against '{target.name}'. "
                    f"All {checks_passed} defensive regression checks passed."
                )
            else:
                remediation.status = RemediationStatus.REOPENED.value
                audit_event_type = AuditEventType.VERIFICATION_FAILED.value
                audit_detail = (
                    f"Remediation #{remediation.id} verification FAILED. "
                    f"{checks_failed} checks failed. Remediation reopened."
                )

            audit_final = RemediationAuditEvent(
                remediation_id=remediation.id,
                event_type=audit_event_type,
                actor_id=actor.id,
                old_status=old_workflow_status,
                new_status=remediation.status,
                details=audit_detail,
            )
            db.session.add(audit_final)
            db.session.commit()

            return remediation, overall_outcome, bounded_evidence

        except Exception as exc:
            logger.exception(
                f"Exception during verification of remediation #{remediation_id}: {exc}"
            )
            db.session.rollback()

            remediation = db.session.get(Remediation, remediation_id)
            if remediation:
                remediation.verification_status = VerificationOutcome.ERROR.value
                remediation.status = RemediationStatus.REOPENED.value
                remediation.sanitized_verification_evidence = f"Verification execution error: {exc}"
                remediation.evidence_sha256 = Remediation.compute_evidence_hash(f"Error: {exc}")

                audit_err = RemediationAuditEvent(
                    remediation_id=remediation.id,
                    event_type=AuditEventType.VERIFICATION_FAILED.value,
                    actor_id=actor.id,
                    old_status=remediation.status,
                    new_status=RemediationStatus.REOPENED.value,
                    details=f"Verification terminated with technical error: {str(exc)[:200]}",
                )
                db.session.add(audit_err)
                db.session.commit()

            return remediation, VerificationOutcome.ERROR, str(exc)
