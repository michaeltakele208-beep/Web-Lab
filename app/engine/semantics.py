"""Standardized vocabulary and semantics for the VADL offensive security testing engine."""

from enum import Enum


class ResultOutcome(str, Enum):
    """Strict result vocabulary for individual security tests."""

    # A controlled test reproduced the documented weakness
    VULNERABILITY_CONFIRMED = "VULNERABILITY_CONFIRMED"

    # The relevant defensive control behaved as expected
    SECURITY_CHECK_PASSED = "SECURITY_CHECK_PASSED"

    # The expected weakness was not reproduced (does not prove target is secure)
    VULNERABILITY_NOT_REPRODUCED = "VULNERABILITY_NOT_REPRODUCED"

    # The test could not produce a trustworthy result (e.g., timeout, crash, unexpected HTTP error)
    ERROR = "ERROR"

    # The test does not apply to the selected target or configuration
    NOT_APPLICABLE = "NOT_APPLICABLE"


class AssessmentStatus(str, Enum):
    """Lifecycle states of an assessment run."""

    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    COMPLETED_WITH_ERRORS = "completed_with_errors"
    FAILED = "failed"
    CANCELLED = "cancelled"


class AuditEventType(str, Enum):
    """Structured audit trail event types for laboratory assessment tracking."""

    REQUESTED = "requested"
    STARTED = "started"
    COMPLETED = "completed"
    FAILED = "failed"
    AUTH_REJECTED = "auth_rejected"
    CANCELLED = "cancelled"

    # Phase 5: Remediation and verification audit events
    REMEDIATION_CREATED = "remediation_created"
    STATUS_CHANGED = "status_changed"
    VERIFICATION_REQUESTED = "verification_requested"
    VERIFICATION_COMPLETED = "verification_completed"
    VERIFICATION_FAILED = "verification_failed"
    REMEDIATION_REOPENED = "remediation_reopened"


class RemediationStatus(str, Enum):
    """Workflow states for vulnerability remediation tracking."""

    OPEN = "OPEN"
    IN_PROGRESS = "IN_PROGRESS"
    READY_FOR_VERIFICATION = "READY_FOR_VERIFICATION"
    VERIFIED = "VERIFIED"
    REOPENED = "REOPENED"


class VerificationOutcome(str, Enum):
    """Technical outcome of a defensive remediation verification execution."""

    # The required defensive checks ran successfully and all applicable checks passed
    VERIFIED = "VERIFIED"

    # At least one required check demonstrated that the vulnerability persists
    FAILED = "FAILED"

    # The test ran but could not establish whether the control is effective
    INCONCLUSIVE = "INCONCLUSIVE"

    # Execution failed or produced an untrustworthy result
    ERROR = "ERROR"

    # The control does not apply to the scenario
    NOT_APPLICABLE = "NOT_APPLICABLE"

    # Initial state before any verification execution
    UNVERIFIED = "UNVERIFIED"


class TargetEdition(str, Enum):
    """Target edition selector for test execution."""

    VULNERABLE = "vulnerable"
    SECURE = "secure"
    BOTH = "both"


class ErrorCategory(str, Enum):
    """Taxonomy of test execution errors."""

    TIMEOUT = "TIMEOUT"
    HTTP_ERROR = "HTTP_ERROR"
    CONNECTION_FAILED = "CONNECTION_FAILED"
    AUTH_FAILURE = "AUTH_FAILURE"
    PARSING_ERROR = "PARSING_ERROR"
    EXECUTION_FAULT = "EXECUTION_FAULT"
    TARGET_DISABLED = "TARGET_DISABLED"
