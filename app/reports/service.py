"""Report orchestration, persistence, and audit logging service (Phase 7)."""

import json
from pathlib import Path
from typing import Any

from app.extensions import db
from app.models.assessment import Assessment, AssessmentAuditEvent
from app.models.report import SecurityReport
from app.models.scanner import ScanAuditEvent, SecurityScan
from app.models.user import Role, User
from app.reports.comparison_service import ScanComparisonService
from app.reports.json_generator import JsonReportGenerator
from app.reports.pdf_generator import PdfReportGenerator
from app.scanner.semantics import ScanAuditEventType


class ReportService:
    """Manages the creation, persistence, storage, and retrieval of security reports."""

    REPORTS_DIR = Path("reports")
    PDF_DIR = REPORTS_DIR / "pdf"
    JSON_DIR = REPORTS_DIR / "json"

    @classmethod
    def _ensure_dirs(cls) -> None:
        cls.PDF_DIR.mkdir(parents=True, exist_ok=True)
        cls.JSON_DIR.mkdir(parents=True, exist_ok=True)

    @classmethod
    def generate_scan_report(
        cls,
        scan: SecurityScan,
        actor: User,
        file_format: str = "pdf",
    ) -> SecurityReport:
        """Generate, persist, and record a SecurityScan report."""
        cls._ensure_dirs()
        generator_pdf = PdfReportGenerator()

        if file_format == "pdf":
            content_bytes = generator_pdf.build_scan_pdf(scan, actor=actor)
            filename = f"scan_{scan.id}_{scan.uuid[:8]}.pdf"
            dest_path = cls.PDF_DIR / filename
            dest_path.write_bytes(content_bytes)
            file_size = len(content_bytes)
        else:
            json_dict = JsonReportGenerator.generate_scan_json(scan, actor=actor)
            json_str = JsonReportGenerator.serialize(json_dict)
            content_bytes = json_str.encode("utf-8")
            filename = f"scan_{scan.id}_{scan.uuid[:8]}.json"
            dest_path = cls.JSON_DIR / filename
            dest_path.write_text(json_str, encoding="utf-8")
            file_size = len(content_bytes)

        report = SecurityReport(
            title=f"Security Scan Report #{scan.id} ({scan.scanner_type.upper()})",
            report_type="SCAN",
            file_format=file_format,
            scan_id=scan.id,
            target_id=scan.target_id,
            generated_by_user_id=actor.id,
            file_path=str(dest_path),
            file_size_bytes=file_size,
            summary_json=json.dumps({
                "total_findings": scan.total_findings,
                "critical": scan.critical_count,
                "high": scan.high_count,
                "medium": scan.medium_count,
                "low": scan.low_count,
                "status": scan.status,
            }),
        )
        db.session.add(report)

        # Audit event
        audit_ev = ScanAuditEvent(
            scan_id=scan.id,
            event_type=ScanAuditEventType.REPORT_GENERATED.value,
            actor_id=actor.id,
            details=f"Generated {file_format.upper()} security scan report #{report.id} ({filename})",
        )
        db.session.add(audit_ev)
        db.session.commit()

        return report

    @classmethod
    def generate_assessment_report(
        cls,
        assessment: Assessment,
        actor: User,
        file_format: str = "pdf",
    ) -> SecurityReport:
        """Generate, persist, and record an offensive Assessment report."""
        cls._ensure_dirs()
        generator_pdf = PdfReportGenerator()

        if file_format == "pdf":
            content_bytes = generator_pdf.build_assessment_pdf(assessment, actor=actor)
            filename = f"assessment_{assessment.id}_{assessment.uuid[:8]}.pdf"
            dest_path = cls.PDF_DIR / filename
            dest_path.write_bytes(content_bytes)
            file_size = len(content_bytes)
        else:
            json_dict = JsonReportGenerator.generate_assessment_json(assessment, actor=actor)
            json_str = JsonReportGenerator.serialize(json_dict)
            content_bytes = json_str.encode("utf-8")
            filename = f"assessment_{assessment.id}_{assessment.uuid[:8]}.json"
            dest_path = cls.JSON_DIR / filename
            dest_path.write_text(json_str, encoding="utf-8")
            file_size = len(content_bytes)

        report = SecurityReport(
            title=f"Assessment Security Report #{assessment.id}",
            report_type="ASSESSMENT",
            file_format=file_format,
            assessment_id=assessment.id,
            target_id=assessment.target_id,
            generated_by_user_id=actor.id,
            file_path=str(dest_path),
            file_size_bytes=file_size,
            summary_json=json.dumps({
                "total_tests": assessment.total_tests,
                "confirmed_vulnerabilities": assessment.confirmed_vulnerabilities,
                "passed_checks": assessment.passed_checks,
                "status": assessment.status,
            }),
        )
        db.session.add(report)

        audit_ev = AssessmentAuditEvent(
            assessment_id=assessment.id,
            event_type="REPORT_GENERATED",
            actor_id=actor.id,
            details=f"Generated {file_format.upper()} assessment report #{report.id} ({filename})",
        )
        db.session.add(audit_ev)
        db.session.commit()

        return report

    @classmethod
    def generate_comparison_report(
        cls,
        scan_a: SecurityScan,
        scan_b: SecurityScan,
        actor: User,
        file_format: str = "pdf",
    ) -> SecurityReport:
        """Generate, persist, and record a scan comparison differential report."""
        cls._ensure_dirs()
        diff = ScanComparisonService.compare_security_scans(scan_a, scan_b)
        generator_pdf = PdfReportGenerator()

        if file_format == "pdf":
            content_bytes = generator_pdf.build_comparison_pdf(diff, actor=actor)
            filename = f"comparison_scan_{scan_a.id}_vs_{scan_b.id}.pdf"
            dest_path = cls.PDF_DIR / filename
            dest_path.write_bytes(content_bytes)
            file_size = len(content_bytes)
        else:
            json_str = json.dumps(diff, indent=2, default=str)
            content_bytes = json_str.encode("utf-8")
            filename = f"comparison_scan_{scan_a.id}_vs_{scan_b.id}.json"
            dest_path = cls.JSON_DIR / filename
            dest_path.write_text(json_str, encoding="utf-8")
            file_size = len(content_bytes)

        report = SecurityReport(
            title=f"Scan Comparison Report: Scan #{scan_a.id} vs Scan #{scan_b.id}",
            report_type="COMPARISON",
            file_format=file_format,
            scan_id=scan_b.id,
            target_id=scan_a.target_id,
            generated_by_user_id=actor.id,
            file_path=str(dest_path),
            file_size_bytes=file_size,
            summary_json=json.dumps({
                "scan_a_id": scan_a.id,
                "scan_b_id": scan_b.id,
                "counts": diff.get("counts", {}),
                "is_conclusive": diff.get("is_conclusive", False),
            }),
        )
        db.session.add(report)

        # Audit events on both scans
        for s in (scan_a, scan_b):
            audit_ev = ScanAuditEvent(
                scan_id=s.id,
                event_type=ScanAuditEventType.SCAN_COMPARISON.value,
                actor_id=actor.id,
                details=f"Scan #{s.id} included in comparison report #{report.id}",
            )
            db.session.add(audit_ev)

        db.session.commit()
        return report

    @classmethod
    def record_download(cls, report: SecurityReport, actor: User) -> None:
        """Increment download counter and log audit event."""
        report.download_count += 1
        if report.scan_id:
            audit_ev = ScanAuditEvent(
                scan_id=report.scan_id,
                event_type=ScanAuditEventType.REPORT_DOWNLOADED.value,
                actor_id=actor.id,
                details=f"Report #{report.id} ({report.file_format.upper()}) downloaded by user #{actor.id} ({actor.email})",
            )
            db.session.add(audit_ev)
        db.session.commit()

    @classmethod
    def validate_access(cls, report: SecurityReport, actor: User) -> bool:
        """Verify actor has permission to access the specified report."""
        if not actor:
            return False
        # Admins and security analysts have broad lab assessment visibility
        if getattr(actor, "is_analyst", False) or actor.role in (Role.ADMIN, Role.SECURITY_ANALYST):
            return True
        # Ordinary users can only access reports they personally generated
        return report.generated_by_user_id == actor.id
