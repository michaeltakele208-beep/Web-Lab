"""Database models for automated security scanning, normalized findings, and scan audit events (Phase 6)."""

import json
import uuid
from datetime import UTC, datetime

from app.extensions import db


class SecurityScan(db.Model):
    """Automated security scan run executing OWASP ZAP, Bandit, or pip-audit."""

    __tablename__ = "security_scans"

    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(
        db.String(36), unique=True, nullable=False, index=True, default=lambda: str(uuid.uuid4())
    )
    scanner_type = db.Column(db.String(30), nullable=False, index=True)
    scan_profile = db.Column(db.String(30), nullable=False, default="baseline")
    status = db.Column(db.String(30), nullable=False, default="QUEUED", index=True)

    target_id = db.Column(
        db.Integer, db.ForeignKey("lab_targets.id", ondelete="SET NULL"), nullable=True
    )
    target_edition = db.Column(db.String(20), nullable=True)
    target_url = db.Column(db.String(500), nullable=True)
    scan_mode = db.Column(db.String(20), nullable=False, default="URL")
    source_path = db.Column(db.String(255), nullable=True)
    initiated_by_user_id = db.Column(
        db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    tool_version = db.Column(db.String(50), nullable=True)
    tool_configuration = db.Column(db.Text, nullable=True)

    score = db.Column(db.Integer, nullable=False, default=100)
    grade = db.Column(db.String(5), nullable=False, default="A")
    grade_breakdown = db.Column(db.Text, nullable=True)

    total_findings = db.Column(db.Integer, nullable=False, default=0)
    critical_count = db.Column(db.Integer, nullable=False, default=0)
    high_count = db.Column(db.Integer, nullable=False, default=0)
    medium_count = db.Column(db.Integer, nullable=False, default=0)
    low_count = db.Column(db.Integer, nullable=False, default=0)
    info_count = db.Column(db.Integer, nullable=False, default=0)

    raw_report_path = db.Column(db.String(255), nullable=True)
    error_message = db.Column(db.Text, nullable=True)

    created_at = db.Column(
        db.DateTime, nullable=False, default=lambda: datetime.now(UTC), index=True
    )
    started_at = db.Column(db.DateTime, nullable=True)
    completed_at = db.Column(db.DateTime, nullable=True)

    # Relationships
    target = db.relationship("LabTarget", backref=db.backref("security_scans", lazy=True))
    initiator = db.relationship("User", backref=db.backref("initiated_scans", lazy=True))
    findings = db.relationship(
        "NormalizedFinding",
        back_populates="scan",
        cascade="all, delete-orphan",
        order_by="NormalizedFinding.id",
    )
    audit_events = db.relationship(
        "ScanAuditEvent",
        back_populates="scan",
        cascade="all, delete-orphan",
        order_by="ScanAuditEvent.id",
    )

    @property
    def breakdown_dict(self) -> dict:
        """Parse grade breakdown JSON safely."""
        if not self.grade_breakdown:
            return {}
        try:
            return json.loads(self.grade_breakdown)
        except (ValueError, TypeError):
            return {}

    @property
    def duration_seconds(self) -> float | None:
        """Calculate total elapsed runtime in seconds."""
        if self.started_at and self.completed_at:
            return round((self.completed_at - self.started_at).total_seconds(), 2)
        return None

    @property
    def configuration_dict(self) -> dict:
        """Parse configuration JSON string safely."""
        if not self.tool_configuration:
            return {}
        try:
            return json.loads(self.tool_configuration)
        except (ValueError, TypeError):
            return {}

    def to_dict(self) -> dict:
        """Serialize security scan record for API consumers."""
        return {
            "id": self.id,
            "uuid": self.uuid,
            "scanner_type": self.scanner_type,
            "scan_profile": self.scan_profile,
            "status": self.status,
            "target_id": self.target_id,
            "target_name": self.target.name if self.target else None,
            "target_edition": self.target_edition,
            "target_url": self.target_url,
            "scan_mode": self.scan_mode,
            "source_path": self.source_path,
            "initiated_by_user_id": self.initiated_by_user_id,
            "tool_version": self.tool_version,
            "score": self.score,
            "grade": self.grade,
            "grade_breakdown": self.breakdown_dict,
            "total_findings": self.total_findings,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "info_count": self.info_count,
            "raw_report_path": self.raw_report_path,
            "error_message": self.error_message,
            "duration_seconds": self.duration_seconds,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }


class NormalizedFinding(db.Model):
    """Normalized security finding conforming to common schema across all scanner tools."""

    __tablename__ = "normalized_findings"

    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(
        db.String(36), unique=True, nullable=False, index=True, default=lambda: str(uuid.uuid4())
    )
    scan_id = db.Column(
        db.Integer, db.ForeignKey("security_scans.id", ondelete="CASCADE"), nullable=False
    )
    scanner_name = db.Column(db.String(30), nullable=False, index=True)
    tool_finding_id = db.Column(db.String(100), nullable=False)

    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(100), nullable=True)
    cwe_id = db.Column(db.String(50), nullable=True)
    owasp_category = db.Column(db.String(100), nullable=True)

    severity = db.Column(db.String(20), nullable=False, index=True)
    original_severity = db.Column(db.String(50), nullable=True)
    confidence = db.Column(db.String(20), nullable=False, default="UNKNOWN")
    original_confidence = db.Column(db.String(50), nullable=True)

    target_component = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(255), nullable=True)
    line_number = db.Column(db.Integer, nullable=True)
    evidence_snippet = db.Column(db.Text, nullable=True)
    remediation_guidance = db.Column(db.Text, nullable=True)
    advisory_url = db.Column(db.String(255), nullable=True)

    fingerprint = db.Column(db.String(64), nullable=False, index=True)
    status = db.Column(db.String(20), nullable=False, default="NEW", index=True)

    is_lab_scenario = db.Column(db.Boolean, nullable=False, default=False)
    scenario_id = db.Column(db.String(50), nullable=True, index=True)
    remediation_id = db.Column(
        db.Integer, db.ForeignKey("remediations.id", ondelete="SET NULL"), nullable=True
    )

    first_seen_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(UTC))
    last_seen_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(UTC))
    created_at = db.Column(
        db.DateTime, nullable=False, default=lambda: datetime.now(UTC), index=True
    )

    # Relationships
    scan = db.relationship("SecurityScan", back_populates="findings")
    remediation = db.relationship("Remediation", backref=db.backref("linked_findings", lazy=True))

    def to_dict(self) -> dict:
        """Serialize normalized finding for API consumers."""
        return {
            "id": self.id,
            "uuid": self.uuid,
            "scan_id": self.scan_id,
            "scanner_name": self.scanner_name,
            "tool_finding_id": self.tool_finding_id,
            "title": self.title,
            "description": self.description,
            "category": self.category,
            "cwe_id": self.cwe_id,
            "owasp_category": self.owasp_category,
            "severity": self.severity,
            "original_severity": self.original_severity,
            "confidence": self.confidence,
            "original_confidence": self.original_confidence,
            "target_component": self.target_component,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "evidence_snippet": self.evidence_snippet,
            "remediation_guidance": self.remediation_guidance,
            "advisory_url": self.advisory_url,
            "fingerprint": self.fingerprint,
            "status": self.status,
            "is_lab_scenario": self.is_lab_scenario,
            "scenario_id": self.scenario_id,
            "remediation_id": self.remediation_id,
            "first_seen_at": self.first_seen_at.isoformat() if self.first_seen_at else None,
            "last_seen_at": self.last_seen_at.isoformat() if self.last_seen_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class ScanAuditEvent(db.Model):
    """Audit trail logging all security scan requests, state transitions, and authorization events."""

    __tablename__ = "scan_audit_events"

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(
        db.Integer, db.ForeignKey("security_scans.id", ondelete="CASCADE"), nullable=True
    )
    event_type = db.Column(db.String(50), nullable=False, index=True)
    actor_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    details = db.Column(db.Text, nullable=False)
    timestamp = db.Column(
        db.DateTime, nullable=False, default=lambda: datetime.now(UTC), index=True
    )

    # Relationships
    scan = db.relationship("SecurityScan", back_populates="audit_events")
    actor = db.relationship("User", backref=db.backref("scan_audit_actions", lazy=True))

    def to_dict(self) -> dict:
        """Serialize audit event record."""
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "event_type": self.event_type,
            "actor_id": self.actor_id,
            "actor_email": self.actor.email if self.actor else None,
            "details": self.details,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
        }
