"""Structured JSON Security Assessment Report Generator (Phase 7)."""

from datetime import UTC, datetime
import json
from typing import Any

from app.models.assessment import Assessment
from app.models.scanner import SecurityScan
from app.models.user import User


class JsonReportGenerator:
    """Generates machine-readable JSON security assessment reports."""

    @classmethod
    def generate_scan_json(
        cls, scan: SecurityScan, actor: User | None = None
    ) -> dict[str, Any]:
        """Convert a SecurityScan and its findings into a structured report dictionary."""
        return {
            "report_metadata": {
                "report_id": scan.uuid,
                "project_name": "Vulnerability Assessment and Defense Lab (VADL)",
                "report_type": "security_scan",
                "generated_at": datetime.now(UTC).isoformat(),
                "generated_by": actor.email if actor else "system",
            },
            "assessment_scope": {
                "target_id": scan.target_id,
                "target_name": scan.target.name if scan.target else "Local Application",
                "target_url": scan.target.base_url if scan.target else (scan.source_path or "app/"),
                "target_edition": scan.target_edition,
                "is_authorized_scope": bool(scan.target.is_authorized) if scan.target else True,
            },
            "scan_execution": {
                "id": scan.id,
                "uuid": scan.uuid,
                "scanner_type": scan.scanner_type,
                "scan_profile": scan.scan_profile,
                "status": scan.status,
                "tool_version": scan.tool_version,
                "duration_seconds": scan.duration_seconds,
                "started_at": scan.started_at.isoformat() if scan.started_at else None,
                "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
                "error_message": scan.error_message,
            },
            "findings_summary": {
                "total_findings": scan.total_findings,
                "critical": scan.critical_count,
                "high": scan.high_count,
                "medium": scan.medium_count,
                "low": scan.low_count,
                "informational": scan.info_count,
            },
            "detailed_findings": [
                {
                    "id": f.id,
                    "title": f.title,
                    "severity": f.severity,
                    "confidence": f.confidence,
                    "status": f.status,
                    "fingerprint": f.fingerprint,
                    "cwe_id": f.cwe_id,
                    "owasp_category": f.owasp_category,
                    "vulnerability_identifier": f.tool_finding_id,
                    "target_component": f.target_component,
                    "description": f.description,
                    "remediation_advice": f.remediation_guidance,
                    "evidence_snippet": f.evidence_snippet,
                    "is_lab_scenario": f.is_lab_scenario,
                    "scenario_id": f.scenario_id,
                    "first_detected_at": f.first_seen_at.isoformat() if f.first_seen_at else None,
                    "last_detected_at": f.last_seen_at.isoformat() if f.last_seen_at else None,
                }
                for f in scan.findings
            ],
            "limitations_and_disclaimer": (
                "Absence of findings does not prove that an application is completely secure. "
                "Automated scanning tools evaluate specific patterns and rule subsets only."
            ),
        }

    @classmethod
    def generate_assessment_json(
        cls, assessment: Assessment, actor: User | None = None
    ) -> dict[str, Any]:
        """Convert an offensive Assessment and its test results into a structured report dictionary."""
        return {
            "report_metadata": {
                "report_id": assessment.uuid,
                "project_name": "Vulnerability Assessment and Defense Lab (VADL)",
                "report_type": "offensive_assessment",
                "generated_at": datetime.now(UTC).isoformat(),
                "generated_by": actor.email if actor else "system",
            },
            "assessment_scope": {
                "target_id": assessment.target_id,
                "target_name": assessment.target.name if assessment.target else f"Target #{assessment.target_id}",
                "target_url": assessment.target.base_url if assessment.target else None,
                "target_edition": assessment.target_edition,
            },
            "execution_summary": {
                "id": assessment.id,
                "uuid": assessment.uuid,
                "status": assessment.status,
                "total_tests": assessment.total_tests,
                "confirmed_vulnerabilities": assessment.confirmed_vulnerabilities,
                "passed_checks": assessment.passed_checks,
                "not_reproduced": assessment.not_reproduced,
                "error_count": assessment.error_count,
                "duration_seconds": assessment.duration_seconds,
                "created_at": assessment.created_at.isoformat(),
                "started_at": assessment.started_at.isoformat() if assessment.started_at else None,
                "completed_at": assessment.completed_at.isoformat() if assessment.completed_at else None,
                "error_message": assessment.error_message,
            },
            "results": [
                {
                    "scenario_id": r.scenario_id,
                    "scenario_name": getattr(r, "scenario_name", None) or r.scenario_id,
                    "outcome": getattr(r, "outcome", getattr(r, "status", "UNKNOWN")),
                    "edition_tested": r.target_edition if hasattr(r, "target_edition") else getattr(r, "edition_tested", "both"),
                    "cwe_id": getattr(r, "cwe_id", None),
                    "owasp_category": getattr(r, "owasp_category", None),
                    "duration_ms": getattr(r, "duration_ms", None),
                    "description": getattr(r, "description", None),
                    "remediation_guidance": getattr(r, "remediation_guidance", None),
                    "evidence": getattr(r, "evidence", getattr(r, "sanitized_evidence", None)),
                }
                for r in assessment.results
            ],
            "limitations_and_disclaimer": (
                "Assessment checks evaluate predefined test cases against lab target editions. "
                "Passing checks verify that specific payloads were neutralized."
            ),
        }

    @classmethod
    def serialize(cls, report_dict: dict[str, Any]) -> str:
        """Serialize report dictionary to formatted JSON string."""
        return json.dumps(report_dict, indent=2, default=str)
