"""Database models for offensive security assessments, test results, and audit events."""

import json
import uuid
from datetime import UTC, datetime

from app.extensions import db


class Assessment(db.Model):
    """Offensive security assessment run against an authorized laboratory target."""

    __tablename__ = "assessments"

    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(
        db.String(36), unique=True, nullable=False, index=True, default=lambda: str(uuid.uuid4())
    )
    target_id = db.Column(
        db.Integer, db.ForeignKey("lab_targets.id", ondelete="CASCADE"), nullable=False
    )
    initiator_id = db.Column(
        db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    status = db.Column(db.String(30), nullable=False, default="queued", index=True)
    selected_scenarios = db.Column(db.Text, nullable=False)  # JSON-serialized list of scenario IDs
    target_edition = db.Column(db.String(20), nullable=False, default="both")

    total_tests = db.Column(db.Integer, nullable=False, default=0)
    passed_checks = db.Column(db.Integer, nullable=False, default=0)
    confirmed_vulnerabilities = db.Column(db.Integer, nullable=False, default=0)
    not_reproduced = db.Column(db.Integer, nullable=False, default=0)
    error_count = db.Column(db.Integer, nullable=False, default=0)

    error_message = db.Column(db.Text, nullable=True)

    created_at = db.Column(
        db.DateTime, nullable=False, default=lambda: datetime.now(UTC), index=True
    )
    started_at = db.Column(db.DateTime, nullable=True)
    completed_at = db.Column(db.DateTime, nullable=True)

    # Relationships
    target = db.relationship("LabTarget", backref=db.backref("assessments", lazy=True))
    initiator = db.relationship("User", backref=db.backref("initiated_assessments", lazy=True))
    results = db.relationship(
        "TestResult",
        back_populates="assessment",
        cascade="all, delete-orphan",
        order_by="TestResult.id",
    )
    audit_events = db.relationship(
        "AssessmentAuditEvent",
        back_populates="assessment",
        cascade="all, delete-orphan",
        order_by="AssessmentAuditEvent.id",
    )

    @property
    def scenarios_list(self) -> list[str]:
        """Deserialize selected scenarios list."""
        try:
            return json.loads(self.selected_scenarios)
        except (ValueError, TypeError):
            return []

    @property
    def duration_seconds(self) -> float | None:
        """Calculate total elapsed assessment runtime."""
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None

    def to_dict(self) -> dict:
        """Serialize assessment metadata for API responses."""
        return {
            "id": self.id,
            "uuid": self.uuid,
            "target_id": self.target_id,
            "target_name": self.target.name if self.target else None,
            "initiator_id": self.initiator_id,
            "initiator_email": self.initiator.email if self.initiator else None,
            "status": self.status,
            "selected_scenarios": self.scenarios_list,
            "target_edition": self.target_edition,
            "total_tests": self.total_tests,
            "passed_checks": self.passed_checks,
            "confirmed_vulnerabilities": self.confirmed_vulnerabilities,
            "not_reproduced": self.not_reproduced,
            "error_count": self.error_count,
            "error_message": self.error_message,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_seconds": self.duration_seconds,
        }


class TestResult(db.Model):
    """Detailed record and forensic evidence of an individual test case execution."""

    __test__ = False  # Prevent pytest from treating model as a test suite
    __tablename__ = "test_results"

    id = db.Column(db.Integer, primary_key=True)
    assessment_id = db.Column(
        db.Integer, db.ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False
    )
    scenario_id = db.Column(db.String(50), nullable=False, index=True)
    test_identifier = db.Column(db.String(100), nullable=False)
    target_edition = db.Column(db.String(20), nullable=False)  # "vulnerable" or "secure"
    outcome = db.Column(db.String(40), nullable=False, index=True)
    error_category = db.Column(db.String(50), nullable=True)

    evidence = db.Column(db.Text, nullable=True)  # Sanitized request/response or forensic details

    started_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(UTC))
    completed_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(UTC))
    duration_ms = db.Column(db.Integer, nullable=True)

    # Relationships
    assessment = db.relationship("Assessment", back_populates="results")

    @property
    def is_vulnerability_confirmed(self) -> bool:
        return self.outcome == "VULNERABILITY_CONFIRMED"

    @property
    def is_security_check_passed(self) -> bool:
        return self.outcome == "SECURITY_CHECK_PASSED"

    def to_dict(self) -> dict:
        """Serialize test result for API responses."""
        return {
            "id": self.id,
            "assessment_id": self.assessment_id,
            "scenario_id": self.scenario_id,
            "test_identifier": self.test_identifier,
            "target_edition": self.target_edition,
            "outcome": self.outcome,
            "error_category": self.error_category,
            "evidence": self.evidence,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_ms": self.duration_ms,
        }


class AssessmentAuditEvent(db.Model):
    """Audit log entry capturing actions across the assessment lifecycle."""

    __tablename__ = "assessment_audit_events"

    id = db.Column(db.Integer, primary_key=True)
    assessment_id = db.Column(
        db.Integer, db.ForeignKey("assessments.id", ondelete="CASCADE"), nullable=True
    )
    event_type = db.Column(db.String(50), nullable=False, index=True)
    actor_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    timestamp = db.Column(
        db.DateTime, nullable=False, default=lambda: datetime.now(UTC), index=True
    )
    details = db.Column(db.Text, nullable=True)  # Sanitized audit information

    # Relationships
    assessment = db.relationship("Assessment", back_populates="audit_events")
    actor = db.relationship("User")

    def to_dict(self) -> dict:
        """Serialize audit event."""
        return {
            "id": self.id,
            "assessment_id": self.assessment_id,
            "event_type": self.event_type,
            "actor_id": self.actor_id,
            "actor_email": self.actor.email if self.actor else None,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "details": self.details,
        }
