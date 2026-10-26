"""Scan comparison and differential security analysis service (Phase 7)."""

from typing import Any

from app.models.assessment import Assessment
from app.models.scanner import SecurityScan
from app.scanner.semantics import ScanLifecycle


class ScanComparisonService:
    """Computes differential vulnerability analysis between two security scans or assessments."""

    @classmethod
    def compare_security_scans(
        cls, scan_a: SecurityScan, scan_b: SecurityScan
    ) -> dict[str, Any]:
        """Compare two automated SecurityScan executions of the same lab target.

        scan_a is treated as baseline/earlier, and scan_b as comparison/later.
        """
        # 1. Target validation
        if scan_a.target_id != scan_b.target_id:
            raise ValueError(
                f"Cannot compare scans across differing lab targets: "
                f"Target #{scan_a.target_id} vs Target #{scan_b.target_id}."
            )

        target_name = scan_a.target.name if scan_a.target else (scan_a.source_path or "Application Repository")

        # 2. Conclusiveness and caveats
        caveats: list[str] = []
        is_conclusive = True

        for scan, label in ((scan_a, "Baseline"), (scan_b, "Comparison")):
            if scan.status in (
                ScanLifecycle.FAILED.value,
                ScanLifecycle.TIMED_OUT.value,
                ScanLifecycle.CANCELLED.value,
            ):
                is_conclusive = False
                caveats.append(
                    f"{label} Scan #{scan.id} terminated with non-completed status '{scan.status}'. "
                    "Comparisons involving failed, cancelled, or timed-out scans cannot establish definitive remediation claims."
                )

        if scan_a.scan_profile != scan_b.scan_profile:
            caveats.append(
                f"Scan execution profiles differ ('{scan_a.scan_profile}' vs '{scan_b.scan_profile}'). "
                "Differences in findings may stem from scanning methodology or rule depth rather than code changes."
            )

        if scan_a.scanner_type != scan_b.scanner_type:
            caveats.append(
                f"Different scanner tools were used ('{scan_a.scanner_type}' vs '{scan_b.scanner_type}'). "
                "Cross-tool findings may not directly correlate due to differing detection heuristics."
            )

        # 3. Categorize findings by fingerprint
        map_a = {f.fingerprint: f for f in scan_a.findings}
        map_b = {f.fingerprint: f for f in scan_b.findings}

        new_fingerprints = set(map_b.keys()) - set(map_a.keys())
        resolved_fingerprints = set(map_a.keys()) - set(map_b.keys())
        persistent_fingerprints = set(map_a.keys()) & set(map_b.keys())

        new_findings = [map_b[fp] for fp in new_fingerprints]
        resolved_findings = [map_a[fp] for fp in resolved_fingerprints]
        persistent_findings = [map_b[fp] for fp in persistent_fingerprints]

        # Check for severity changes among persistent findings
        severity_changes: list[dict[str, Any]] = []
        for fp in persistent_fingerprints:
            fa = map_a[fp]
            fb = map_b[fp]
            if fa.severity != fb.severity:
                severity_changes.append(
                    {
                        "fingerprint": fp,
                        "title": fb.title,
                        "old_severity": fa.severity,
                        "new_severity": fb.severity,
                        "finding_id": fb.id,
                    }
                )

        # Explicit explanation of missing findings
        caveats.append(
            "Note: Absence of a previously detected finding in the comparison scan indicates it was not observed, "
            "but does not constitute formal proof of remediation unless verified through dedicated regression checks."
        )

        return {
            "comparison_type": "security_scan",
            "target_id": scan_a.target_id,
            "target_name": target_name,
            "is_conclusive": is_conclusive,
            "scan_a": {
                "id": scan_a.id,
                "uuid": scan_a.uuid,
                "scanner_type": scan_a.scanner_type,
                "profile": scan_a.scan_profile,
                "status": scan_a.status,
                "total_findings": scan_a.total_findings,
                "created_at": scan_a.created_at,
            },
            "scan_b": {
                "id": scan_b.id,
                "uuid": scan_b.uuid,
                "scanner_type": scan_b.scanner_type,
                "profile": scan_b.scan_profile,
                "status": scan_b.status,
                "total_findings": scan_b.total_findings,
                "created_at": scan_b.created_at,
            },
            "counts": {
                "new": len(new_findings),
                "resolved": len(resolved_findings),
                "persistent": len(persistent_findings),
                "severity_changes": len(severity_changes),
            },
            "new_findings": new_findings,
            "resolved_findings": resolved_findings,
            "persistent_findings": persistent_findings,
            "severity_changes": severity_changes,
            "caveats": caveats,
        }

    @classmethod
    def compare_assessments(
        cls, assessment_a: Assessment, assessment_b: Assessment
    ) -> dict[str, Any]:
        """Compare two offensive security assessments of the same lab target."""
        if assessment_a.target_id != assessment_b.target_id:
            raise ValueError(
                f"Cannot compare assessments across differing lab targets: "
                f"Target #{assessment_a.target_id} vs Target #{assessment_b.target_id}."
            )

        target_name = assessment_a.target.name if assessment_a.target else f"Target #{assessment_a.target_id}"

        caveats: list[str] = []
        is_conclusive = True

        for asm, label in ((assessment_a, "Baseline"), (assessment_b, "Comparison")):
            if asm.status in ("failed", "cancelled"):
                is_conclusive = False
                caveats.append(
                    f"{label} Assessment #{asm.id} finished with status '{asm.status}'. "
                    "Incomplete assessments cannot be used for definitive remediation assertions."
                )

        results_a = {r.scenario_id: r for r in assessment_a.results}
        results_b = {r.scenario_id: r for r in assessment_b.results}

        all_scenarios = sorted(set(results_a.keys()) | set(results_b.keys()))

        remediated_scenarios: list[dict[str, Any]] = []
        new_vulnerabilities: list[dict[str, Any]] = []
        persistent_vulnerabilities: list[dict[str, Any]] = []
        consistent_passes: list[dict[str, Any]] = []

        for sc_id in all_scenarios:
            ra = results_a.get(sc_id)
            rb = results_b.get(sc_id)

            if not ra or not rb:
                continue

            item = {
                "scenario_id": sc_id,
                "scenario_name": getattr(rb, "scenario_name", None) or getattr(ra, "scenario_name", None) or sc_id,
                "baseline_status": getattr(ra, "outcome", getattr(ra, "status", "UNKNOWN")),
                "comparison_status": getattr(rb, "outcome", getattr(rb, "status", "UNKNOWN")),
            }

            ra_vuln = getattr(ra, "outcome", getattr(ra, "status", "")) in ("VULNERABILITY_CONFIRMED", "CONFIRMED_VULNERABLE")
            rb_vuln = getattr(rb, "outcome", getattr(rb, "status", "")) in ("VULNERABILITY_CONFIRMED", "CONFIRMED_VULNERABLE")
            ra_pass = getattr(ra, "outcome", getattr(ra, "status", "")) in ("SECURITY_CHECK_PASSED", "PASSED")
            rb_pass = getattr(rb, "outcome", getattr(rb, "status", "")) in ("SECURITY_CHECK_PASSED", "PASSED")

            if ra_vuln and rb_pass:
                remediated_scenarios.append(item)
            elif ra_pass and rb_vuln:
                new_vulnerabilities.append(item)
            elif ra_vuln and rb_vuln:
                persistent_vulnerabilities.append(item)
            elif ra_pass and rb_pass:
                consistent_passes.append(item)

        return {
            "comparison_type": "assessment",
            "target_id": assessment_a.target_id,
            "target_name": target_name,
            "is_conclusive": is_conclusive,
            "assessment_a": {
                "id": assessment_a.id,
                "uuid": assessment_a.uuid,
                "status": assessment_a.status,
                "confirmed_vulnerabilities": assessment_a.confirmed_vulnerabilities,
                "created_at": assessment_a.created_at,
            },
            "assessment_b": {
                "id": assessment_b.id,
                "uuid": assessment_b.uuid,
                "status": assessment_b.status,
                "confirmed_vulnerabilities": assessment_b.confirmed_vulnerabilities,
                "created_at": assessment_b.created_at,
            },
            "counts": {
                "remediated": len(remediated_scenarios),
                "new": len(new_vulnerabilities),
                "persistent": len(persistent_vulnerabilities),
                "consistent_passes": len(consistent_passes),
            },
            "remediated_scenarios": remediated_scenarios,
            "new_vulnerabilities": new_vulnerabilities,
            "persistent_vulnerabilities": persistent_vulnerabilities,
            "consistent_passes": consistent_passes,
            "caveats": caveats,
        }
