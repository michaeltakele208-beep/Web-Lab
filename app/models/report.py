"""Database model for security reports, report generation tracking, and download auditing (Phase 7)."""

import uuid
from datetime import UTC, datetime

from app.extensions import db


class SecurityReport(db.Model):
    """Generated executive or technical security assessment report record."""

    __tablename__ = "security_reports"

    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(
        db.String(36), unique=True, nullable=False, index=True, default=lambda: str(uuid.uuid4())
    )
    title = db.Column(db.String(255), nullable=False)
    report_type = db.Column(
        db.String(32), nullable=False, index=True
    )  # SCAN, ASSESSMENT, COMPREHENSIVE, COMPARISON
    file_format = db.Column(db.String(10), nullable=False, default="pdf")  # pdf, json

    scan_id = db.Column(
        db.Integer, db.ForeignKey("security_scans.id", ondelete="SET NULL"), nullable=True
    )
    assessment_id = db.Column(
        db.Integer, db.ForeignKey("assessments.id", ondelete="SET NULL"), nullable=True
    )
    target_id = db.Column(
        db.Integer, db.ForeignKey("lab_targets.id", ondelete="SET NULL"), nullable=True
    )
    generated_by_user_id = db.Column(
        db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    file_path = db.Column(db.String(255), nullable=False)
    file_size_bytes = db.Column(db.Integer, nullable=False, default=0)
    download_count = db.Column(db.Integer, nullable=False, default=0)

    summary_json = db.Column(db.Text, nullable=True)

    created_at = db.Column(
        db.DateTime, nullable=False, default=lambda: datetime.now(UTC), index=True
    )

    # Relationships
    scan = db.relationship("SecurityScan", backref=db.backref("reports", lazy=True))
    assessment = db.relationship("Assessment", backref=db.backref("reports", lazy=True))
    target = db.relationship("LabTarget", backref=db.backref("reports", lazy=True))
    generator = db.relationship("User", backref=db.backref("generated_reports", lazy=True))

    def __repr__(self) -> str:
        return f"<SecurityReport {self.id}:{self.report_type}:{self.file_format}>"
