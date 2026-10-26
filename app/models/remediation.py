"""Database models for vulnerability remediation tracking and verification audit trail."""

import hashlib
import uuid
from datetime import UTC, datetime

from app.extensions import db


class Remediation(db.Model):
    """Vulnerability remediation tracking record with defensive verification lifecycle."""

    __tablename__ = "remediations"

    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(
        db.String(36), unique=True, nullable=False, index=True, default=lambda: str(uuid.uuid4())
    )
    scenario_id = db.Column(db.String(50), nullable=False, index=True)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=True)
    remediation_details = db.Column(db.Text, nullable=True)

    # Workflow Status: OPEN, IN_PROGRESS, READY_FOR_VERIFICATION, VERIFIED, REOPENED
    status = db.Column(db.String(30), nullable=False, default="OPEN", index=True)

    # Technical Verification Outcome: UNVERIFIED, VERIFIED, FAILED, INCONCLUSIVE, ERROR
    verification_status = db.Column(db.String(30), nullable=False, default="UNVERIFIED", index=True)

    # Foreign key references to original finding and assessment
    finding_result_id = db.Column(
        db.Integer, db.ForeignKey("test_results.id", ondelete="SET NULL"), nullable=True
    )
    original_assessment_id = db.Column(
        db.Integer, db.ForeignKey("assessments.id", ondelete="SET NULL"), nullable=True
    )

    # Foreign key references to verification run
    verification_result_id = db.Column(
        db.Integer, db.ForeignKey("test_results.id", ondelete="SET NULL"), nullable=True
    )
    verification_assessment_id = db.Column(
        db.Integer, db.ForeignKey("assessments.id", ondelete="SET NULL"), nullable=True
    )

    # User references
    assigned_user_id = db.Column(
        db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_by_user_id = db.Column(
        db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    verified_by_user_id = db.Column(
        db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    verified_at = db.Column(db.DateTime, nullable=True)
    sanitized_verification_evidence = db.Column(db.Text, nullable=True)

    # SHA-256 evidence integrity digest for tamper detection
    evidence_sha256 = db.Column(db.String(64), nullable=True)

    created_at = db.Column(
        db.DateTime, nullable=False, default=lambda: datetime.now(UTC), index=True
    )
    updated_at = db.Column(
        db.DateTime,
        nullable=False,
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )

    # Relationships
    finding_result = db.relationship("TestResult", foreign_keys=[finding_result_id])
    original_assessment = db.relationship("Assessment", foreign_keys=[original_assessment_id])
    verification_result = db.relationship("TestResult", foreign_keys=[verification_result_id])
    verification_assessment = db.relationship(
        "Assessment", foreign_keys=[verification_assessment_id]
    )

    assigned_user = db.relationship("User", foreign_keys=[assigned_user_id])
    created_by = db.relationship("User", foreign_keys=[created_by_user_id])
    verified_by = db.relationship("User", foreign_keys=[verified_by_user_id])

    audit_events = db.relationship(
        "RemediationAuditEvent",
        back_populates="remediation",
        cascade="all, delete-orphan",
        order_by="RemediationAuditEvent.id",
    )

    @property
    def is_verified(self) -> bool:
        """Check if both workflow status and verification outcome confirm resolution."""
        return self.status == "VERIFIED" and self.verification_status == "VERIFIED"

    @property
    def is_reopened(self) -> bool:
        return self.status == "REOPENED"

    @staticmethod
    def compute_evidence_hash(evidence_text: str | None) -> str | None:
        """Compute SHA-256 digest of sanitized evidence to detect modification."""
        if not evidence_text:
            return None
        return hashlib.sha256(evidence_text.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict:
        """Serialize remediation record for API consumption."""
        return {
            "id": self.id,
            "uuid": self.uuid,
            "scenario_id": self.scenario_id,
            "title": self.title,
            "description": self.description,
            "remediation_details": self.remediation_details,
            "status": self.status,
            "verification_status": self.verification_status,
            "finding_result_id": self.finding_result_id,
            "original_assessment_id": self.original_assessment_id,
            "verification_result_id": self.verification_result_id,
            "verification_assessment_id": self.verification_assessment_id,
            "assigned_user_id": self.assigned_user_id,
            "assigned_user_email": self.assigned_user.email if self.assigned_user else None,
            "created_by_user_id": self.created_by_user_id,
            "created_by_email": self.created_by.email if self.created_by else None,
            "verified_by_user_id": self.verified_by_user_id,
            "verified_by_email": self.verified_by.email if self.verified_by else None,
            "verified_at": self.verified_at.isoformat() if self.verified_at else None,
            "evidence_sha256": self.evidence_sha256,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class RemediationAuditEvent(db.Model):
    """Audit log entry capturing state transitions and actions in the remediation lifecycle."""

    __tablename__ = "remediation_audit_events"

    id = db.Column(db.Integer, primary_key=True)
    remediation_id = db.Column(
        db.Integer, db.ForeignKey("remediations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    event_type = db.Column(db.String(50), nullable=False, index=True)
    actor_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    old_status = db.Column(db.String(30), nullable=True)
    new_status = db.Column(db.String(30), nullable=True)

    timestamp = db.Column(
        db.DateTime, nullable=False, default=lambda: datetime.now(UTC), index=True
    )
    details = db.Column(db.Text, nullable=True)

    # Relationships
    remediation = db.relationship("Remediation", back_populates="audit_events")
    actor = db.relationship("User")

    def to_dict(self) -> dict:
        """Serialize audit log entry."""
        return {
            "id": self.id,
            "remediation_id": self.remediation_id,
            "event_type": self.event_type,
            "actor_id": self.actor_id,
            "actor_email": self.actor.email if self.actor else None,
            "old_status": self.old_status,
            "new_status": self.new_status,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "details": self.details,
        }
