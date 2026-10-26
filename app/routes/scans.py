"""Automated security scanning routes, dashboard, and JSON API (Phase 6)."""

import json
import logging
from datetime import UTC, datetime
from pathlib import Path

from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)
from werkzeug.utils import secure_filename

from app.engine.target_guard import AuthorizationError
from app.extensions import db
from app.models.lab import LabTarget
from app.models.scanner import NormalizedFinding, ScanAuditEvent, SecurityScan
from app.models.user import Role
from app.scanner.adapters.registry import get_all_scanners
from app.scanner.orchestrator import ScannerOrchestrator
from app.scanner.semantics import (
    FindingStatus,
    NormalizedSeverity,
    ScanAuditEventType,
    ScanLifecycle,
)
from app.scanner.url_inspector import inspect_url
from app.scanner.zip_inspector import ZipAuditError, inspect_zip
from app.security import get_current_user, role_required

logger = logging.getLogger("vadl.routes.scans")

scans_bp = Blueprint("scans", __name__, url_prefix="/scans")


def wants_json_response() -> bool:
    """Detect whether client expects JSON response."""
    return (
        request.is_json
        or request.path.startswith("/api/")
        or (request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html)
    )


@scans_bp.route("", methods=["GET"])
@role_required(Role.SECURITY_ANALYST, Role.ADMIN)
def index():
    """Security scanning console displaying tool availability, scan history, and launch controls."""
    scanners = get_all_scanners()
    targets = LabTarget.query.filter_by(is_authorized=True).all()

    # Recent scans
    scans_query = SecurityScan.query.order_by(SecurityScan.created_at.desc()).limit(25).all()

    # Metrics
    total_scans = SecurityScan.query.count()
    completed_scans = SecurityScan.query.filter(
        SecurityScan.status.in_(
            [ScanLifecycle.COMPLETED.value, ScanLifecycle.COMPLETED_WITH_FINDINGS.value]
        )
    ).count()
    total_findings = NormalizedFinding.query.count()

    if wants_json_response():
        return jsonify(
            {
                "scanners": scanners,
                "recent_scans": [s.to_dict() for s in scans_query],
                "total_scans": total_scans,
                "completed_scans": completed_scans,
                "total_findings": total_findings,
            }
        )

    return render_template(
        "scans/index.html",
        scanners=scanners,
        targets=targets,
        recent_scans=scans_query,
        stats={
            "total_scans": total_scans,
            "completed_scans": completed_scans,
            "total_findings": total_findings,
        },
    )


@scans_bp.route("/run", methods=["POST"])
@role_required(Role.SECURITY_ANALYST, Role.ADMIN)
def run_scan():
    """Trigger an automated security scan (OWASP ZAP, Bandit, or pip-audit)."""
    user = get_current_user()

    if request.is_json:
        data = request.get_json() or {}
        scanner_type = (data.get("scanner_type") or "").strip()
        raw_target_id = data.get("target_id")
        target_edition = data.get("target_edition")
        source_dir = (data.get("source_dir") or "app").strip()
        profile = (data.get("profile") or "baseline").strip()
        allow_active = bool(data.get("allow_active_scan", False))
        options = data.get("options") or {}
    else:
        scanner_type = (request.form.get("scanner_type") or "").strip()
        raw_target_id = request.form.get("target_id")
        target_edition = request.form.get("target_edition")
        source_dir = (request.form.get("source_dir") or "app").strip()
        profile = (request.form.get("profile") or "baseline").strip()
        allow_active = request.form.get("allow_active_scan") == "on"
        options = {}

    target_id = int(raw_target_id) if raw_target_id else None
    if allow_active:
        options["allow_active_scan"] = True

    timeout_seconds = current_app.config.get("SCAN_TIMEOUT_SECONDS", 120)

    try:
        scan = ScannerOrchestrator.run_scan(
            actor=user,
            scanner_type=scanner_type,
            target_id=target_id,
            target_edition=target_edition,
            source_dir=source_dir,
            profile=profile,
            timeout_seconds=timeout_seconds,
            options=options,
        )

        if wants_json_response():
            return jsonify(scan.to_dict()), 201

        if scan.status == ScanLifecycle.COMPLETED_WITH_FINDINGS.value:
            flash(
                f"Scan #{scan.id} completed. Identified {scan.total_findings} security findings.",
                "warning",
            )
        elif scan.status == ScanLifecycle.COMPLETED.value:
            flash(f"Scan #{scan.id} completed cleanly. 0 security findings reported.", "success")
        elif scan.status == ScanLifecycle.TIMED_OUT.value:
            flash(f"Scan #{scan.id} exceeded execution timeout ({timeout_seconds}s).", "danger")
        else:
            flash(f"Scan #{scan.id} failed: {scan.error_message}", "danger")

        return redirect(url_for("scans.detail", scan_id=scan.id))

    except AuthorizationError as exc:
        if wants_json_response():
            return jsonify({"error": str(exc)}), 403
        flash(str(exc), "danger")
        return redirect(url_for("scans.index"))
    except ValueError as exc:
        if wants_json_response():
            return jsonify({"error": str(exc)}), 400
        flash(str(exc), "danger")
        return redirect(url_for("scans.index"))
    except Exception as exc:
        logger.exception(f"Unexpected error launching scan: {exc}")
        if wants_json_response():
            return jsonify(
                {"error": "An unexpected error occurred while initiating the scan."}
            ), 500
        flash("An unexpected error occurred while initiating the scan.", "danger")
        return redirect(url_for("scans.index"))


@scans_bp.route("/url", methods=["POST"])
@role_required(Role.SECURITY_ANALYST, Role.ADMIN)
def scan_url():
    """Execute live passive security inspection of target website URL."""
    user = get_current_user()
    if request.is_json:
        data = request.get_json() or {}
        target_url = (data.get("target_url") or "").strip()
    else:
        target_url = (request.form.get("target_url") or "").strip()

    if not target_url:
        if wants_json_response():
            return jsonify({"error": "Target URL is required."}), 400
        flash("Target URL cannot be empty.", "danger")
        return redirect(url_for("scans.index"))

    now = datetime.now(UTC)
    result = inspect_url(target_url)
    findings_raw = result["findings"]
    grade_res = result["grade_result"]

    c_count = sum(1 for f in findings_raw if f.get("severity") == "CRITICAL")
    h_count = sum(1 for f in findings_raw if f.get("severity") == "HIGH")
    m_count = sum(1 for f in findings_raw if f.get("severity") == "MEDIUM")
    l_count = sum(1 for f in findings_raw if f.get("severity") == "LOW")
    i_count = sum(1 for f in findings_raw if f.get("severity") in ("INFO", "INFORMATIONAL"))

    scan = SecurityScan(
        scanner_type="URL_INSPECTOR",
        scan_profile="headers_and_tls",
        scan_mode="URL",
        target_url=result["target_url"],
        status=(
            ScanLifecycle.COMPLETED_WITH_FINDINGS.value
            if findings_raw
            else ScanLifecycle.COMPLETED.value
        ),
        tool_version="2.0.0",
        tool_configuration=json.dumps(
            {
                "status_code": result.get("status_code", 0),
                "response_time_ms": result.get("response_time_ms", 0.0),
                "server_headers": result.get("server_headers", {}),
            }
        ),
        score=grade_res["score"],
        grade=grade_res["grade"],
        grade_breakdown=json.dumps(grade_res),
        total_findings=len(findings_raw),
        critical_count=c_count,
        high_count=h_count,
        medium_count=m_count,
        low_count=l_count,
        info_count=i_count,
        initiated_by_user_id=user.id,
        created_at=now,
        started_at=now,
        completed_at=datetime.now(UTC),
    )
    db.session.add(scan)
    db.session.flush()

    for f in findings_raw:
        nf = NormalizedFinding(
            scan_id=scan.id,
            scanner_name="URL_INSPECTOR",
            tool_finding_id=f.get("title", "Finding"),
            title=f.get("title", "Security Finding"),
            description=f.get("description", ""),
            category=f.get("category", "Security Headers"),
            cwe_id=f.get("cwe_id"),
            severity=f.get("severity", "LOW"),
            confidence=f.get("confidence", "HIGH"),
            target_component=f.get("target_component", result["target_url"]),
            evidence_snippet=f.get("evidence_snippet", ""),
            remediation_guidance=f.get("remediation_guidance", ""),
            fingerprint=f.get("fingerprint")
            or ScannerOrchestrator.compute_fingerprint(
                scanner_name="URL_INSPECTOR",
                tool_finding_id=f.get("title", ""),
                target_component=result["target_url"],
            ),
            status=FindingStatus.NEW.value,
            created_at=now,
            first_seen_at=now,
            last_seen_at=now,
        )
        db.session.add(nf)

    audit_event = ScanAuditEvent(
        scan_id=scan.id,
        event_type=ScanAuditEventType.SCAN_COMPLETED.value,
        actor_id=user.id,
        details=f"URL inspection of '{result['target_url']}' completed: Grade {scan.grade} (Score: {scan.score}/100) with {scan.total_findings} findings.",
        timestamp=datetime.now(UTC),
    )
    db.session.add(audit_event)
    db.session.commit()

    if wants_json_response():
        return jsonify(scan.to_dict()), 201

    flash(
        f"Inspection completed for '{result['target_url']}': Grade {scan.grade} (Score {scan.score}/100) with {scan.total_findings} findings.",
        "success" if scan.score >= 80 else ("warning" if scan.score >= 60 else "danger"),
    )
    return redirect(url_for("scans.detail", scan_id=scan.id))


@scans_bp.route("/zip", methods=["POST"])
@role_required(Role.SECURITY_ANALYST, Role.ADMIN)
def scan_zip():
    """Execute static security analysis (Bandit SAST + pip-audit SCA) on uploaded project ZIP archive."""
    user = get_current_user()
    if "file" not in request.files:
        if wants_json_response():
            return jsonify({"error": "No file uploaded in request."}), 400
        flash("Please select a .zip project archive to upload.", "danger")
        return redirect(url_for("scans.index"))

    uploaded_file = request.files["file"]
    if not uploaded_file or not uploaded_file.filename:
        if wants_json_response():
            return jsonify({"error": "Empty filename."}), 400
        flash("No archive selected.", "danger")
        return redirect(url_for("scans.index"))

    safe_name = secure_filename(uploaded_file.filename)
    if not safe_name.lower().endswith(".zip"):
        if wants_json_response():
            return jsonify({"error": "Only .zip project archives are supported."}), 400
        flash("Only .zip archives are supported.", "danger")
        return redirect(url_for("scans.index"))

    now = datetime.now(UTC)
    try:
        result = inspect_zip(uploaded_file, filename=safe_name)
    except ZipAuditError as exc:
        if wants_json_response():
            return jsonify({"error": str(exc)}), 400
        flash(f"Archive audit rejected: {exc}", "danger")
        return redirect(url_for("scans.index"))
    except Exception as exc:
        logger.exception(f"ZIP audit failed: {exc}")
        if wants_json_response():
            return jsonify({"error": f"Internal scan error: {exc}"}), 500
        flash(f"Scan failed: {exc}", "danger")
        return redirect(url_for("scans.index"))

    findings_raw = result["findings"]
    grade_res = result["grade_result"]

    c_count = sum(1 for f in findings_raw if f.get("severity") == "CRITICAL")
    h_count = sum(1 for f in findings_raw if f.get("severity") == "HIGH")
    m_count = sum(1 for f in findings_raw if f.get("severity") == "MEDIUM")
    l_count = sum(1 for f in findings_raw if f.get("severity") == "LOW")
    i_count = sum(1 for f in findings_raw if f.get("severity") in ("INFO", "INFORMATIONAL"))

    scan = SecurityScan(
        scanner_type="ZIP_AUDIT",
        scan_profile="sast_and_sca",
        scan_mode="ZIP",
        target_url=f"Project Archive: {safe_name}",
        source_path=safe_name,
        status=(
            ScanLifecycle.COMPLETED_WITH_FINDINGS.value
            if findings_raw
            else ScanLifecycle.COMPLETED.value
        ),
        tool_version="2.0.0",
        tool_configuration=json.dumps(
            {
                "filename": safe_name,
                "files_analyzed": result.get("files_analyzed", 0),
                "python_files": result.get("python_files_count", 0),
                "has_dependencies": result.get("has_dependencies", False),
            }
        ),
        score=grade_res["score"],
        grade=grade_res["grade"],
        grade_breakdown=json.dumps(grade_res),
        total_findings=len(findings_raw),
        critical_count=c_count,
        high_count=h_count,
        medium_count=m_count,
        low_count=l_count,
        info_count=i_count,
        initiated_by_user_id=user.id,
        created_at=now,
        started_at=now,
        completed_at=datetime.now(UTC),
    )
    db.session.add(scan)
    db.session.flush()

    for f in findings_raw:
        nf = NormalizedFinding(
            scan_id=scan.id,
            scanner_name="ZIP_AUDIT",
            tool_finding_id=f.get("title", "Finding"),
            title=f.get("title", "Security Finding"),
            description=f.get("description", ""),
            category=f.get("category", "Static Code Quality"),
            cwe_id=f.get("cwe_id"),
            severity=f.get("severity", "LOW"),
            confidence=f.get("confidence", "HIGH"),
            target_component=f.get("target_component", safe_name),
            file_path=f.get("file_path"),
            line_number=f.get("line_number"),
            evidence_snippet=f.get("evidence_snippet", ""),
            remediation_guidance=f.get("remediation_guidance", ""),
            fingerprint=f.get("fingerprint")
            or ScannerOrchestrator.compute_fingerprint(
                scanner_name="ZIP_AUDIT",
                tool_finding_id=f.get("title", ""),
                target_component=f.get("target_component", safe_name),
            ),
            status=FindingStatus.NEW.value,
            created_at=now,
            first_seen_at=now,
            last_seen_at=now,
        )
        db.session.add(nf)

    audit_event = ScanAuditEvent(
        scan_id=scan.id,
        event_type=ScanAuditEventType.SCAN_COMPLETED.value,
        actor_id=user.id,
        details=f"ZIP Archive audit of '{safe_name}' completed: Grade {scan.grade} (Score: {scan.score}/100) with {scan.total_findings} findings.",
        timestamp=datetime.now(UTC),
    )
    db.session.add(audit_event)
    db.session.commit()

    if wants_json_response():
        return jsonify(scan.to_dict()), 201

    flash(
        f"Archive '{safe_name}' audited: Grade {scan.grade} (Score {scan.score}/100) across {result.get('files_analyzed', 0)} files with {scan.total_findings} findings.",
        "success" if scan.score >= 80 else ("warning" if scan.score >= 60 else "danger"),
    )
    return redirect(url_for("scans.detail", scan_id=scan.id))


@scans_bp.route("/<int:scan_id>", methods=["GET"])
@role_required(Role.SECURITY_ANALYST, Role.ADMIN)
def detail(scan_id: int):
    """Inspect detailed scan run metadata, findings breakdown, and raw report references."""
    scan = db.session.get(SecurityScan, scan_id)
    if not scan:
        abort(404, description=f"Security scan #{scan_id} not found.")

    findings = (
        NormalizedFinding.query.filter_by(scan_id=scan.id)
        .order_by(
            db.case(
                {
                    NormalizedSeverity.CRITICAL.value: 1,
                    NormalizedSeverity.HIGH.value: 2,
                    NormalizedSeverity.MEDIUM.value: 3,
                    NormalizedSeverity.LOW.value: 4,
                    NormalizedSeverity.INFORMATIONAL.value: 5,
                },
                value=NormalizedFinding.severity,
            )
        )
        .all()
    )

    if wants_json_response():
        data = scan.to_dict()
        data["findings"] = [f.to_dict() for f in findings]
        data["audit_events"] = [e.to_dict() for e in scan.audit_events]
        return jsonify(data)

    return render_template(
        "scans/detail.html",
        scan=scan,
        findings=findings,
    )


@scans_bp.route("/<int:scan_id>/report", methods=["GET"])
@role_required(Role.SECURITY_ANALYST, Role.ADMIN)
def download_report(scan_id: int):
    """Download the raw machine-readable JSON report generated by the scanner tool."""
    scan = db.session.get(SecurityScan, scan_id)
    if not scan:
        abort(404, description=f"Security scan #{scan_id} not found.")

    if not scan.raw_report_path:
        abort(404, description="No raw report artifact is associated with this scan.")

    report_path = Path(scan.raw_report_path).resolve()
    reports_base = Path("reports/scans").resolve()

    # Prevent path traversal: ensure path resides strictly within reports/scans directory
    if not str(report_path).startswith(str(reports_base)) or not report_path.exists():
        abort(404, description="Raw report artifact file does not exist or access is restricted.")

    return send_file(
        report_path,
        mimetype="application/json",
        as_attachment=True,
        download_name=f"vadl_scan_{scan.uuid}_{scan.scanner_type}.json",
    )


@scans_bp.route("/findings", methods=["GET"])
@role_required(Role.SECURITY_ANALYST, Role.ADMIN)
def findings_list():
    """Consolidated findings browser with multi-dimensional filtering and search."""
    severity_filter = request.args.get("severity")
    scanner_filter = request.args.get("scanner")
    status_filter = request.args.get("status")
    query_str = (request.args.get("q") or "").strip().lower()

    query = NormalizedFinding.query

    if severity_filter:
        query = query.filter_by(severity=severity_filter.upper())
    if scanner_filter:
        query = query.filter_by(scanner_name=scanner_filter.lower())
    if status_filter:
        query = query.filter_by(status=status_filter.upper())
    if query_str:
        like_pattern = f"%{query_str}%"
        query = query.filter(
            db.or_(
                NormalizedFinding.title.ilike(like_pattern),
                NormalizedFinding.description.ilike(like_pattern),
                NormalizedFinding.target_component.ilike(like_pattern),
            )
        )

    # Sort critical/high first, then by recency
    findings = (
        query.order_by(
            db.case(
                {
                    NormalizedSeverity.CRITICAL.value: 1,
                    NormalizedSeverity.HIGH.value: 2,
                    NormalizedSeverity.MEDIUM.value: 3,
                    NormalizedSeverity.LOW.value: 4,
                    NormalizedSeverity.INFORMATIONAL.value: 5,
                },
                value=NormalizedFinding.severity,
            ),
            NormalizedFinding.created_at.desc(),
        )
        .limit(100)
        .all()
    )

    if wants_json_response():
        return jsonify(
            {
                "findings": [f.to_dict() for f in findings],
                "total": len(findings),
            }
        )

    return render_template(
        "scans/findings.html",
        findings=findings,
        severity_filter=severity_filter,
        scanner_filter=scanner_filter,
        status_filter=status_filter,
        query_str=query_str,
    )


@scans_bp.route("/findings/<int:finding_id>", methods=["GET"])
@role_required(Role.SECURITY_ANALYST, Role.ADMIN)
def finding_detail(finding_id: int):
    """Detailed forensic inspection view for an individual normalized finding."""
    finding = db.session.get(NormalizedFinding, finding_id)
    if not finding:
        abort(404, description=f"Finding #{finding_id} not found.")

    if wants_json_response():
        return jsonify(finding.to_dict())

    return render_template(
        "scans/finding_detail.html",
        finding=finding,
    )
