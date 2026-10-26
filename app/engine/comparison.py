"""Before-and-after finding comparison and verification delta service (Phase 5)."""

import json
import logging
from typing import Any

from app.engine.semantics import ResultOutcome, VerificationOutcome
from app.lab.registry import get_scenario
from app.models.assessment import TestResult
from app.models.remediation import Remediation

logger = logging.getLogger("vadl.engine.comparison")


class ComparisonService:
    """Service generating structured differential comparisons between vulnerable findings and defensive verification."""

    @classmethod
    def compare_remediation(cls, remediation: Remediation) -> dict[str, Any]:
        """Generate a structured before-and-after comparison between original finding and verification result."""
        scenario = get_scenario(remediation.scenario_id)

        # 1. Resolve original finding
        finding: TestResult | None = remediation.finding_result
        verification: TestResult | None = remediation.verification_result

        # Compatibility check: both must belong to the same scenario
        is_compatible = True
        compatibility_notes = []

        if not finding:
            is_compatible = False
            compatibility_notes.append(
                "No original assessment finding is linked to this remediation."
            )
        elif finding.scenario_id != remediation.scenario_id:
            is_compatible = False
            compatibility_notes.append(
                f"Scenario mismatch: Original finding is '{finding.scenario_id}', "
                f"remediation target is '{remediation.scenario_id}'."
            )

        if not verification:
            is_compatible = False
            compatibility_notes.append("Defensive verification has not yet been executed.")
        elif verification.scenario_id != remediation.scenario_id:
            is_compatible = False
            compatibility_notes.append(
                f"Scenario mismatch: Verification result is '{verification.scenario_id}', "
                f"remediation target is '{remediation.scenario_id}'."
            )

        # 2. Extract structured evidence payloads if available
        finding_data = cls._parse_evidence(finding.evidence if finding else None)
        verification_data = cls._parse_evidence(verification.evidence if verification else None)

        # 3. Determine control delta and behavioral change
        delta_summary = "Incomplete Comparison"
        remediation_confirmed = False

        if is_compatible and finding and verification:
            vulnerable_confirmed = finding.outcome == ResultOutcome.VULNERABILITY_CONFIRMED.value
            secure_passed = (
                verification.outcome == ResultOutcome.SECURITY_CHECK_PASSED.value
                or remediation.verification_status == VerificationOutcome.VERIFIED.value
            )

            if vulnerable_confirmed and secure_passed:
                delta_summary = "Vulnerability Successfully Remediated"
                remediation_confirmed = True
            elif vulnerable_confirmed and not secure_passed:
                delta_summary = "Remediation Ineffective: Vulnerability Still Observable"
            elif not vulnerable_confirmed:
                delta_summary = "Original Finding Inconclusive"

        return {
            "remediation_id": remediation.id,
            "scenario_id": remediation.scenario_id,
            "scenario_title": scenario.title if scenario else remediation.scenario_id,
            "category": scenario.category if scenario else "Unknown",
            "owasp_reference": scenario.owasp_reference if scenario else "N/A",
            "is_compatible": is_compatible,
            "compatibility_notes": compatibility_notes,
            "delta_summary": delta_summary,
            "remediation_confirmed": remediation_confirmed,
            "before": {
                "assessment_id": remediation.original_assessment_id,
                "result_id": finding.id if finding else None,
                "edition": finding.target_edition if finding else "vulnerable",
                "outcome": finding.outcome if finding else "N/A",
                "timestamp": finding.completed_at.isoformat()
                if finding and finding.completed_at
                else None,
                "evidence_parsed": finding_data,
                "raw_evidence": finding.evidence if finding else None,
            },
            "after": {
                "assessment_id": remediation.verification_assessment_id,
                "result_id": verification.id if verification else None,
                "edition": verification.target_edition if verification else "secure",
                "outcome": verification.outcome if verification else "N/A",
                "verification_status": remediation.verification_status,
                "timestamp": verification.completed_at.isoformat()
                if verification and verification.completed_at
                else None,
                "evidence_sha256": remediation.evidence_sha256,
                "evidence_parsed": verification_data,
                "raw_evidence": remediation.sanitized_verification_evidence,
            },
        }

    @staticmethod
    def _parse_evidence(evidence_text: str | None) -> dict[str, Any] | None:
        """Attempt to parse evidence JSON artifact."""
        if not evidence_text:
            return None
        try:
            # Check if evidence is JSON
            clean = evidence_text.strip()
            if clean.startswith("{") and clean.endswith("}"):
                return json.loads(clean)
        except (json.JSONDecodeError, ValueError):
            logger.debug("Evidence payload is not JSON formatted; keeping raw representation.")
        return None
