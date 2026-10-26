"""Security assessment report routes, downloads, and comparison views (Phase 7)."""

import logging
from pathlib import Path

from flask import (
    Blueprint,
    abort,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)

from app.extensions import db
from app.models.assessment import Assessment
from app.models.lab import LabTarget
from app.models.report import SecurityReport
from app.models.scanner import SecurityScan
from app.models.user import Role
from app.reports.comparison_service import ScanComparisonService
from app.reports.service import ReportService
from app.security import get_current_user, role_required

logger = logging.getLogger("vadl.reports")

reports_bp = Blueprint("reports", __name__, url_prefix="/reports")


def wants_json_response() -> bool:
    """Check if the requesting client explicitly requests a JSON response."""
    return (
        request.is_json
        or request.path.startswith("/api/")
        or request.args.get("format") == "json"
        or (request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html)
    )


@reports_bp.route("", methods=["GET"])
@role_required(Role.SECURITY_ANALYST, Role.ADMIN)
def index():
    """Render the central security reports repository with filtering."""
    report_type_filter = request.args.get("type", "").strip().upper()
    format_filter = request.args.get("format", "").strip().lower()

    query = SecurityReport.query

    if report_type_filter:
        query = query.filter_by(report_type=report_type_filter)
    if format_filter in ("pdf", "json"):
        query = query.filter_by(file_format=format_filter)

    reports = query.order_by(SecurityReport.created_at.desc()).all()

    # Pre-fetch available scans and assessments for the report generation modal
    recent_scans = SecurityScan.query.order_by(SecurityScan.id.desc()).limit(15).all()
    recent_assessments = Assessment.query.order_by(Assessment.id.desc()).limit(15).all()
    targets = LabTarget.query.filter_by(is_authorized=True).all()

    return render_template(
        "reports/index.html",
        reports=reports,
        recent_scans=recent_scans,
        recent_assessments=recent_assessments,
        targets=targets,
        current_type=report_type_filter,
        current_format=format_filter,
    )


@reports_bp.route("/<int:report_id>/download", methods=["GET"])
@role_required(Role.SECURITY_ANALYST, Role.ADMIN)
def download_report(report_id: int):
    """Download a generated security report with authorization and audit logging."""
    report = db.session.get(SecurityReport, report_id)
    if not report:
        abort(404, description=f"Security report #{report_id} not found.")

    actor = get_current_user()
    if not ReportService.validate_access(report, actor):
        abort(403, description="Access to this security report is unauthorized.")

    file_path = Path(report.file_path).resolve()
    reports_root = Path("reports").resolve()

    # Path traversal protection
    if not str(file_path).startswith(str(reports_root)) or not file_path.is_file():
        logger.error("Attempted unauthorized or invalid report file access: %s", report.file_path)
        abort(404, description="Report file artifact does not exist on filesystem.")

    # Record download audit event
    ReportService.record_download(report, actor)

    mimetype = "application/pdf" if report.file_format == "pdf" else "application/json"
    download_name = file_path.name

    return send_file(
        file_path,
        mimetype=mimetype,
        as_attachment=True,
        download_name=download_name,
    )


@reports_bp.route("/generate", methods=["POST"])
@role_required(Role.SECURITY_ANALYST, Role.ADMIN)
def generate():
    """Generate a new PDF or JSON report on demand."""
    actor = get_current_user()
    report_type = request.form.get("report_type", "scan").strip().lower()
    file_format = request.form.get("file_format", "pdf").strip().lower()
    if file_format not in ("pdf", "json"):
        file_format = "pdf"

    try:
        if report_type == "scan":
            scan_id = int(request.form.get("scan_id", 0))
            scan = db.session.get(SecurityScan, scan_id)
            if not scan:
                flash(f"Security scan #{scan_id} does not exist.", "danger")
                return redirect(url_for("reports.index"))
            report = ReportService.generate_scan_report(scan, actor=actor, file_format=file_format)
            flash(
                f"Security scan report #{report.id} ({file_format.upper()}) generated successfully.",
                "success",
            )

        elif report_type == "assessment":
            assessment_id = int(request.form.get("assessment_id", 0))
            asm = db.session.get(Assessment, assessment_id)
            if not asm:
                flash(f"Assessment #{assessment_id} does not exist.", "danger")
                return redirect(url_for("reports.index"))
            report = ReportService.generate_assessment_report(
                asm, actor=actor, file_format=file_format
            )
            flash(
                f"Assessment report #{report.id} ({file_format.upper()}) generated successfully.",
                "success",
            )

        elif report_type == "comparison":
            scan_a_id = int(request.form.get("scan_a_id", 0))
            scan_b_id = int(request.form.get("scan_b_id", 0))
            scan_a = db.session.get(SecurityScan, scan_a_id)
            scan_b = db.session.get(SecurityScan, scan_b_id)
            if not scan_a or not scan_b:
                flash("Both scans must exist for comparison report generation.", "danger")
                return redirect(url_for("reports.index"))
            report = ReportService.generate_comparison_report(
                scan_a, scan_b, actor=actor, file_format=file_format
            )
            flash(
                f"Comparison report #{report.id} ({file_format.upper()}) generated successfully.",
                "success",
            )

        else:
            flash(f"Unknown report type '{report_type}'.", "danger")

    except Exception as exc:
        logger.exception("Failed to generate security report: %s", exc)
        flash(f"Report generation error: {exc}", "danger")

    return redirect(url_for("reports.index"))


@reports_bp.route("/scan/<int:scan_id>/pdf", methods=["GET"])
@role_required(Role.SECURITY_ANALYST, Role.ADMIN)
def download_scan_pdf(scan_id: int):
    """Directly generate or download PDF report for a security scan."""
    scan = db.session.get(SecurityScan, scan_id)
    if not scan:
        abort(404, description=f"Security scan #{scan_id} not found.")

    actor = get_current_user()
    report = ReportService.generate_scan_report(scan, actor=actor, file_format="pdf")
    return redirect(url_for("reports.download_report", report_id=report.id))


@reports_bp.route("/scan/<int:scan_id>/json", methods=["GET"])
@role_required(Role.SECURITY_ANALYST, Role.ADMIN)
def download_scan_json(scan_id: int):
    """Directly generate or download JSON report for a security scan."""
    scan = db.session.get(SecurityScan, scan_id)
    if not scan:
        abort(404, description=f"Security scan #{scan_id} not found.")

    actor = get_current_user()
    report = ReportService.generate_scan_report(scan, actor=actor, file_format="json")
    return redirect(url_for("reports.download_report", report_id=report.id))


@reports_bp.route("/assessment/<int:assessment_id>/pdf", methods=["GET"])
@role_required(Role.SECURITY_ANALYST, Role.ADMIN)
def download_assessment_pdf(assessment_id: int):
    """Directly generate or download PDF report for an assessment."""
    asm = db.session.get(Assessment, assessment_id)
    if not asm:
        abort(404, description=f"Assessment #{assessment_id} not found.")

    actor = get_current_user()
    report = ReportService.generate_assessment_report(asm, actor=actor, file_format="pdf")
    return redirect(url_for("reports.download_report", report_id=report.id))


@reports_bp.route("/assessment/<int:assessment_id>/json", methods=["GET"])
@role_required(Role.SECURITY_ANALYST, Role.ADMIN)
def download_assessment_json(assessment_id: int):
    """Directly generate or download JSON report for an assessment."""
    asm = db.session.get(Assessment, assessment_id)
    if not asm:
        abort(404, description=f"Assessment #{assessment_id} not found.")

    actor = get_current_user()
    report = ReportService.generate_assessment_report(asm, actor=actor, file_format="json")
    return redirect(url_for("reports.download_report", report_id=report.id))


@reports_bp.route("/compare", methods=["GET", "POST"])
@role_required(Role.SECURITY_ANALYST, Role.ADMIN)
def compare():
    """Interactive scan comparison console and trend analysis view."""
    scans = SecurityScan.query.order_by(SecurityScan.id.desc()).all()
    targets = LabTarget.query.all()

    scan_a_id = request.values.get("scan_a_id", type=int)
    scan_b_id = request.values.get("scan_b_id", type=int)

    diff = None
    error_msg = None

    if scan_a_id and scan_b_id:
        if scan_a_id == scan_b_id:
            error_msg = "Please select two distinct scans to perform a comparison."
        else:
            scan_a = db.session.get(SecurityScan, scan_a_id)
            scan_b = db.session.get(SecurityScan, scan_b_id)
            if not scan_a or not scan_b:
                error_msg = "One or both selected scans could not be located in the database."
            else:
                try:
                    diff = ScanComparisonService.compare_security_scans(scan_a, scan_b)
                    if wants_json_response():
                        return jsonify(diff)
                except ValueError as val_err:
                    error_msg = str(val_err)

    if wants_json_response() and error_msg:
        return jsonify({"error": error_msg}), 400

    return render_template(
        "reports/compare.html",
        scans=scans,
        targets=targets,
        scan_a_id=scan_a_id,
        scan_b_id=scan_b_id,
        diff=diff,
        error_msg=error_msg,
    )
