"""Target authorization guard and assessment boundary validator."""

import logging
from typing import Any

from app.engine.semantics import AuditEventType
from app.extensions import db
from app.lab.registry import get_scenario
from app.lab.target_validator import validate_lab_target_url
from app.models.lab import LabTarget
from app.models.user import Role, User

logger = logging.getLogger("vadl.engine.guard")

APPROVED_ENVIRONMENTS = {"development", "testing"}
VALID_EDITIONS = {"vulnerable", "secure", "both"}


class AuthorizationError(Exception):
    """Raised when an assessment request violates authorization or target safety boundaries."""

    def __init__(self, message: str, reason: str = "FORBIDDEN"):
        super().__init__(message)
        self.message = message
        self.reason = reason


def record_auth_rejection(
    user_id: int | None,
    target_id: int | None,
    reason: str,
    details: dict[str, Any] | None = None,
) -> None:
    """Record an audit event when an assessment is rejected at the security boundary."""
    from app.models.assessment import AssessmentAuditEvent

    try:
        audit = AssessmentAuditEvent(
            assessment_id=None,
            event_type=AuditEventType.AUTH_REJECTED.value,
            actor_id=user_id,
            details=f"Reason: {reason} | Details: {details or {}}",
        )
        db.session.add(audit)
        db.session.commit()
    except Exception as exc:
        logger.error(f"Failed to record auth rejection audit event: {exc}")
        db.session.rollback()


def validate_assessment_request(
    user: User | None,
    target_id: int,
    scenario_ids: list[str],
    target_edition: str = "both",
    max_scenarios: int = 10,
) -> LabTarget:
    """Validate user authorization, target configuration, and scenario support.

    Returns the validated LabTarget or raises AuthorizationError.
    """
    # 1. Initiator role verification
    if not user:
        record_auth_rejection(None, target_id, "ANONYMOUS_ACCESS_DENIED")
        raise AuthorizationError("Authentication is required to initiate security assessments.")

    if user.role not in (Role.SECURITY_ANALYST, Role.ADMIN):
        record_auth_rejection(user.id, target_id, "INSUFFICIENT_PRIVILEGES", {"role": user.role})
        raise AuthorizationError(
            f"User role '{user.role}' is not authorized to execute security testing.",
            reason="INSUFFICIENT_ROLE",
        )

    # 2. Target existence and authorization
    target = db.session.get(LabTarget, target_id)
    if not target:
        record_auth_rejection(user.id, target_id, "TARGET_NOT_FOUND")
        raise AuthorizationError(
            f"Target ID {target_id} does not exist.", reason="TARGET_NOT_FOUND"
        )

    if not target.is_authorized:
        record_auth_rejection(
            user.id, target_id, "TARGET_UNAUTHORIZED", {"target_name": target.name}
        )
        raise AuthorizationError(
            f"Target '{target.name}' is not currently authorized for security assessments.",
            reason="TARGET_UNAUTHORIZED",
        )

    # 3. Environment check
    if target.environment_id not in APPROVED_ENVIRONMENTS:
        record_auth_rejection(
            user.id,
            target_id,
            "UNAPPROVED_ENVIRONMENT",
            {"environment": target.environment_id},
        )
        raise AuthorizationError(
            f"Target environment '{target.environment_id}' is not an approved laboratory environment.",
            reason="UNAPPROVED_ENVIRONMENT",
        )

    # 4. Target URL safety re-validation (defense-in-depth)
    is_valid, msg = validate_lab_target_url(target.base_url)
    if not is_valid:
        record_auth_rejection(user.id, target_id, "INVALID_TARGET_URL", {"msg": msg})
        raise AuthorizationError(
            f"Target URL violates safety constraints: {msg}", reason="URL_INVALID"
        )

    # 5. Edition verification
    if target_edition not in VALID_EDITIONS:
        raise AuthorizationError(
            f"Invalid target edition '{target_edition}'. Must be one of {sorted(VALID_EDITIONS)}.",
            reason="INVALID_EDITION",
        )

    # 6. Scenarios verification
    if not scenario_ids:
        raise AuthorizationError(
            "At least one scenario must be selected for assessment.", reason="EMPTY_SCENARIOS"
        )

    if len(scenario_ids) > max_scenarios:
        raise AuthorizationError(
            f"Requested {len(scenario_ids)} scenarios, exceeding maximum limit of {max_scenarios}.",
            reason="LIMIT_EXCEEDED",
        )

    for sid in scenario_ids:
        scenario = get_scenario(sid)
        if not scenario:
            raise AuthorizationError(
                f"Scenario '{sid}' is not registered in the scenario registry.",
                reason="UNKNOWN_SCENARIO",
            )

    return target


def recheck_target_authorization(target_id: int) -> tuple[bool, str]:
    """Re-verify target authorization immediately before test execution.

    Handles race conditions where target authorization was revoked while queued.
    """
    target = db.session.get(LabTarget, target_id)
    if not target:
        return False, f"Target ID {target_id} no longer exists."
    if not target.is_authorized:
        return False, f"Target '{target.name}' authorization was revoked while queued."
    if target.environment_id not in APPROVED_ENVIRONMENTS:
        return (
            False,
            f"Target environment '{target.environment_id}' is not an approved lab environment.",
        )
    return True, "Authorized"
