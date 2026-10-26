"""Offensive security testing engine package for VADL."""

from app.engine.comparison import ComparisonService
from app.engine.evidence import build_evidence, sanitize_text, truncate_evidence
from app.engine.orchestrator import AssessmentOrchestrator, DuplicateAssessmentError
from app.engine.semantics import (
    AssessmentStatus,
    AuditEventType,
    ErrorCategory,
    RemediationStatus,
    ResultOutcome,
    TargetEdition,
    VerificationOutcome,
)
from app.engine.target_guard import (
    AuthorizationError,
    recheck_target_authorization,
    validate_assessment_request,
)
from app.engine.verification import VerificationService

__all__ = [
    "AssessmentOrchestrator",
    "AssessmentStatus",
    "AuditEventType",
    "AuthorizationError",
    "ComparisonService",
    "DuplicateAssessmentError",
    "ErrorCategory",
    "RemediationStatus",
    "ResultOutcome",
    "TargetEdition",
    "VerificationOutcome",
    "VerificationService",
    "build_evidence",
    "recheck_target_authorization",
    "sanitize_text",
    "truncate_evidence",
    "validate_assessment_request",
]
