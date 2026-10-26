"""Primary dashboard route aggregating laboratory metrics, scan history, and remediations (Phase 7)."""

from flask import Blueprint, jsonify, render_template, request
from sqlalchemy import func

from app.extensions import db
from app.models.assessment import Assessment, TestResult
from app.models.lab import LabTarget
from app.models.remediation import Remediation
from app.models.scanner import NormalizedFinding, SecurityScan
from app.scanner.semantics import FindingStatus, NormalizedSeverity, ScanLifecycle
from app.security import get_current_user

dashboard_bp = Blueprint("dashboard", __name__)


def wants_json_response() -> bool:
    """Check if the requesting client explicitly requests a JSON response."""
    return (
        request.is_json
        or request.path.startswith("/api/")
        or request.args.get("format") == "json"
        or (request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html)
    )


@dashboard_bp.route("/dashboard", methods=["GET"])
@dashboard_bp.route("/", methods=["GET"])
def index():
    """Render the central security operations dashboard."""
    user = get_current_user()

    # =========================================================================
    # Section A: Overview Metrics (Calculated from persisted database records)
    # =========================================================================

    # 1. Scans metrics
    count_security_scans = db.session.query(func.count(SecurityScan.id)).scalar() or 0
    count_assessments = db.session.query(func.count(Assessment.id)).scalar() or 0
    total_scans = count_security_scans + count_assessments

    completed_scans = (
        db.session.query(func.count(SecurityScan.id))
        .filter(
            SecurityScan.status.in_(
                [
                    ScanLifecycle.COMPLETED.value,
                    ScanLifecycle.COMPLETED_WITH_FINDINGS.value,
                ]
            )
        )
        .scalar()
        or 0
    ) + (
        db.session.query(func.count(Assessment.id))
        .filter(Assessment.status == "completed")
        .scalar()
        or 0
    )

    failed_scans = (
        db.session.query(func.count(SecurityScan.id))
        .filter(
            SecurityScan.status.in_(
                [
                    ScanLifecycle.FAILED.value,
                    ScanLifecycle.TIMED_OUT.value,
                    ScanLifecycle.CANCELLED.value,
                ]
            )
        )
        .scalar()
        or 0
    ) + (
        db.session.query(func.count(Assessment.id))
        .filter(Assessment.status.in_(["failed", "cancelled"]))
        .scalar()
        or 0
    )

    # 2. Findings metrics
    # Distinct vulnerabilities tracked (by fingerprint) vs open findings
    total_distinct_findings = (
        db.session.query(func.count(func.distinct(NormalizedFinding.fingerprint))).scalar() or 0
    )
    total_finding_records = db.session.query(func.count(NormalizedFinding.id)).scalar() or 0

    open_findings = (
        db.session.query(func.count(NormalizedFinding.id))
        .filter(
            NormalizedFinding.status.in_(
                [
                    FindingStatus.NEW.value,
                    FindingStatus.ACTIVE.value,
                ]
            )
        )
        .scalar()
        or 0
    )

    confirmed_vulnerabilities = (
        db.session.query(func.count(TestResult.id))
        .filter(TestResult.outcome == "VULNERABILITY_CONFIRMED")
        .scalar()
        or 0
    )

    # 3. Remediation metrics
    verified_remediations = (
        db.session.query(func.count(Remediation.id))
        .filter(
            Remediation.status == "VERIFIED",
            Remediation.verification_status == "VERIFIED",
        )
        .scalar()
        or 0
    )

    pending_remediations = (
        db.session.query(func.count(Remediation.id))
        .filter(
            Remediation.status.in_(
                [
                    "OPEN",
                    "IN_PROGRESS",
                    "READY_FOR_VERIFICATION",
                    "REOPENED",
                ]
            )
        )
        .scalar()
        or 0
    )

    failed_verifications = (
        db.session.query(func.count(Remediation.id))
        .filter(Remediation.verification_status == "FAILED")
        .scalar()
        or 0
    )

    inconclusive_verifications = (
        db.session.query(func.count(Remediation.id))
        .filter(Remediation.verification_status == "INCONCLUSIVE")
        .scalar()
        or 0
    )

    # Overall Security Posture Grade
    scored_scans = SecurityScan.query.filter(SecurityScan.score.isnot(None)).all()
    if scored_scans:
        avg_score = round(sum(s.score for s in scored_scans) / len(scored_scans))
        if avg_score >= 95:
            overall_posture_grade = "A+"
        elif avg_score >= 90:
            overall_posture_grade = "A"
        elif avg_score >= 80:
            overall_posture_grade = "B"
        elif avg_score >= 70:
            overall_posture_grade = "C"
        elif avg_score >= 60:
            overall_posture_grade = "D"
        else:
            overall_posture_grade = "F"
    else:
        avg_score = 100
        overall_posture_grade = "A+"

    # 4. Severity Distribution (Active & New Findings)
    severity_counts = {
        "CRITICAL": (
            db.session.query(func.count(NormalizedFinding.id))
            .filter(
                NormalizedFinding.severity == NormalizedSeverity.CRITICAL.value,
                NormalizedFinding.status.in_([FindingStatus.NEW.value, FindingStatus.ACTIVE.value]),
            )
            .scalar()
            or 0
        ),
        "HIGH": (
            db.session.query(func.count(NormalizedFinding.id))
            .filter(
                NormalizedFinding.severity == NormalizedSeverity.HIGH.value,
                NormalizedFinding.status.in_([FindingStatus.NEW.value, FindingStatus.ACTIVE.value]),
            )
            .scalar()
            or 0
        ),
        "MEDIUM": (
            db.session.query(func.count(NormalizedFinding.id))
            .filter(
                NormalizedFinding.severity == NormalizedSeverity.MEDIUM.value,
                NormalizedFinding.status.in_([FindingStatus.NEW.value, FindingStatus.ACTIVE.value]),
            )
            .scalar()
            or 0
        ),
        "LOW": (
            db.session.query(func.count(NormalizedFinding.id))
            .filter(
                NormalizedFinding.severity == NormalizedSeverity.LOW.value,
                NormalizedFinding.status.in_([FindingStatus.NEW.value, FindingStatus.ACTIVE.value]),
            )
            .scalar()
            or 0
        ),
        "INFORMATIONAL": (
            db.session.query(func.count(NormalizedFinding.id))
            .filter(
                NormalizedFinding.severity == NormalizedSeverity.INFORMATIONAL.value,
                NormalizedFinding.status.in_([FindingStatus.NEW.value, FindingStatus.ACTIVE.value]),
            )
            .scalar()
            or 0
        ),
    }

    # =========================================================================
    # Section B: Scan History (with Pagination and Type/Status Filters)
    # =========================================================================
    scan_type_filter = request.args.get("scan_type", "").strip().lower()
    scan_status_filter = request.args.get("status", "").strip().upper()
    page = request.args.get("page", 1, type=int)
    per_page = 10

    # Build unified recent scans
    scans_query = SecurityScan.query
    if scan_status_filter:
        scans_query = scans_query.filter(SecurityScan.status == scan_status_filter)
    scans_list = scans_query.order_by(SecurityScan.created_at.desc()).limit(20).all()

    assessments_query = Assessment.query
    if scan_status_filter:
        assessments_query = assessments_query.filter(
            Assessment.status == scan_status_filter.lower()
        )
    assessments_list = assessments_query.order_by(Assessment.created_at.desc()).limit(20).all()

    combined_scans = []
    if scan_type_filter != "assessment":
        for s in scans_list:
            combined_scans.append(
                {
                    "id": s.id,
                    "uuid": s.uuid,
                    "kind": "scanner",
                    "tool_type": s.scanner_type.upper(),
                    "profile": s.scan_profile,
                    "target_name": s.target.name
                    if s.target
                    else (s.source_path or "Application Repo"),
                    "initiator_id": s.initiated_by_user_id,
                    "created_at": s.created_at,
                    "completed_at": s.completed_at,
                    "duration": s.duration_seconds,
                    "status": s.status,
                    "score": s.score,
                    "grade": s.grade,
                    "target_url": s.target_url,
                    "scan_mode": s.scan_mode,
                    "findings_count": s.total_findings,
                    "detail_url": f"/scans/{s.id}",
                }
            )

    if scan_type_filter != "scanner":
        for a in assessments_list:
            combined_scans.append(
                {
                    "id": a.id,
                    "uuid": a.uuid,
                    "kind": "assessment",
                    "tool_type": "OFFENSIVE ADAPTER",
                    "profile": a.target_edition,
                    "target_name": a.target.name if a.target else f"Target #{a.target_id}",
                    "initiator_id": a.initiator_id,
                    "created_at": a.created_at,
                    "completed_at": a.completed_at,
                    "duration": a.duration_seconds,
                    "status": a.status.upper(),
                    "findings_count": a.confirmed_vulnerabilities,
                    "detail_url": f"/assessments/{a.id}",
                }
            )

    # Sort combined history chronologically descending
    combined_scans.sort(key=lambda x: x["created_at"], reverse=True)

    # Slice for pagination
    total_combined = len(combined_scans)
    start_idx = (page - 1) * per_page
    end_idx = start_idx + per_page
    paginated_scans = combined_scans[start_idx:end_idx]
    total_pages = max(1, (total_combined + per_page - 1) // per_page)

    # =========================================================================
    # Section C: Findings Overview (Filtered)
    # =========================================================================
    severity_filter = request.args.get("severity", "").strip().upper()
    scanner_filter = request.args.get("scanner", "").strip().lower()
    finding_status_filter = request.args.get("finding_status", "").strip().upper()
    target_filter = request.args.get("target_id", type=int)

    findings_query = NormalizedFinding.query
    if severity_filter:
        findings_query = findings_query.filter(NormalizedFinding.severity == severity_filter)
    if scanner_filter:
        findings_query = findings_query.filter(NormalizedFinding.scanner_name == scanner_filter)
    if finding_status_filter:
        findings_query = findings_query.filter(NormalizedFinding.status == finding_status_filter)
    if target_filter:
        findings_query = findings_query.join(SecurityScan).filter(
            SecurityScan.target_id == target_filter
        )

    recent_findings = findings_query.order_by(NormalizedFinding.id.desc()).limit(15).all()

    # Pre-fetch lab targets for filter dropdown
    targets = LabTarget.query.all()

    # =========================================================================
    # Section D: Remediation Overview
    # =========================================================================
    recent_remediations = Remediation.query.order_by(Remediation.id.desc()).limit(8).all()

    if wants_json_response():
        return jsonify(
            {
                "metrics": {
                    "total_scans": total_scans,
                    "completed_scans": completed_scans,
                    "failed_scans": failed_scans,
                    "total_distinct_findings": total_distinct_findings,
                    "total_finding_records": total_finding_records,
                    "open_findings": open_findings,
                    "confirmed_vulnerabilities": confirmed_vulnerabilities,
                    "verified_remediations": verified_remediations,
                    "pending_remediations": pending_remediations,
                    "failed_verifications": failed_verifications,
                    "inconclusive_verifications": inconclusive_verifications,
                    "severity_counts": severity_counts,
                    "avg_score": avg_score,
                    "overall_posture_grade": overall_posture_grade,
                }
            }
        )

    return render_template(
        "dashboard.html",
        user=user,
        avg_score=avg_score,
        overall_posture_grade=overall_posture_grade,
        # Section A
        total_scans=total_scans,
        completed_scans=completed_scans,
        failed_scans=failed_scans,
        total_distinct_findings=total_distinct_findings,
        total_finding_records=total_finding_records,
        open_findings=open_findings,
        confirmed_vulnerabilities=confirmed_vulnerabilities,
        verified_remediations=verified_remediations,
        pending_remediations=pending_remediations,
        failed_verifications=failed_verifications,
        inconclusive_verifications=inconclusive_verifications,
        severity_counts=severity_counts,
        # Section B
        scans=paginated_scans,
        current_page=page,
        total_pages=total_pages,
        total_scans_count=total_combined,
        current_scan_type=scan_type_filter,
        current_status=scan_status_filter,
        # Section C
        recent_findings=recent_findings,
        targets=targets,
        current_severity=severity_filter,
        current_scanner=scanner_filter,
        current_finding_status=finding_status_filter,
        current_target_id=target_filter,
        # Section D
        recent_remediations=recent_remediations,
    )
