"""Defensive remediation workflow and verification routes (Phase 5)."""

import logging
from datetime import UTC, datetime

from flask import Blueprint, abort, flash, jsonify, redirect, render_template, request, url_for

from app.engine.comparison import ComparisonService
from app.engine.semantics import AuditEventType, RemediationStatus, VerificationOutcome
from app.engine.target_guard import AuthorizationError
from app.engine.verification import VerificationService
from app.extensions import db
from app.lab.registry import get_all_scenarios, get_scenario
from app.models.assessment import TestResult
from app.models.lab import LabTarget
from app.models.remediation import Remediation, RemediationAuditEvent
from app.models.user import Role, User
from app.security import get_current_user, role_required

logger = logging.getLogger("vadl.routes.remediations")

remediations_bp = Blueprint("remediations", __name__, url_prefix="/remediations")


def wants_json_response() -> bool:
    """Check if the requesting client explicitly requests a JSON response."""
    return (
        request.is_json
        or request.path.startswith("/api/")
        or (request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html)
    )


@remediations_bp.route("", methods=["GET"])
@role_required(Role.SECURITY_ANALYST, Role.ADMIN)
def index():
    """Remediation tracking dashboard with workflow filters and eligible findings."""
    status_filter = request.args.get("status")
    query = Remediation.query.order_by(Remediation.created_at.desc())

    if status_filter:
        query = query.filter_by(status=status_filter)

    remediations = query.all()

    # Find unlinked vulnerability findings eligible for remediation tracking
    linked_finding_ids = [
        r.finding_result_id
        for r in Remediation.query.filter(Remediation.finding_result_id.isnot(None)).all()
    ]
    eligible_findings_query = TestResult.query.filter_by(outcome="VULNERABILITY_CONFIRMED")
    if linked_finding_ids:
        eligible_findings_query = eligible_findings_query.filter(
            TestResult.id.notin_(linked_finding_ids)
        )
    eligible_findings = eligible_findings_query.order_by(TestResult.id.desc()).limit(15).all()

    if wants_json_response():
        return jsonify(
            {
                "remediations": [r.to_dict() for r in remediations],
                "eligible_findings": [f.to_dict() for f in eligible_findings],
                "total": len(remediations),
            }
        )

    # Calculate status counts for dashboard stats cards
    all_remediations = Remediation.query.all()
    stats = {
        "total": len(all_remediations),
        "open": sum(1 for r in all_remediations if r.status in ("OPEN", "IN_PROGRESS")),
        "ready": sum(1 for r in all_remediations if r.status == "READY_FOR_VERIFICATION"),
        "verified": sum(1 for r in all_remediations if r.status == "VERIFIED"),
        "reopened": sum(1 for r in all_remediations if r.status == "REOPENED"),
    }

    return render_template(
        "remediations/index.html",
        remediations=remediations,
        eligible_findings=eligible_findings,
        stats=stats,
        status_filter=status_filter,
    )


@remediations_bp.route("/new", methods=["GET"])
@role_required(Role.SECURITY_ANALYST, Role.ADMIN)
def new_remediation():
    """Render creation form for new remediation record."""
    finding_id = request.args.get("finding_id", type=int)
    prefill_finding = None
    if finding_id:
        prefill_finding = db.session.get(TestResult, finding_id)

    scenarios = get_all_scenarios()
    analysts = User.query.filter(User.role.in_([Role.SECURITY_ANALYST, Role.ADMIN])).all()

    return render_template(
        "remediations/new.html",
        scenarios=scenarios,
        prefill_finding=prefill_finding,
        analysts=analysts,
    )


@remediations_bp.route("", methods=["POST"])
@role_required(Role.SECURITY_ANALYST, Role.ADMIN)
def create_remediation():
    """Create a new remediation record linked to a scenario and optional finding."""
    user = get_current_user()

    if request.is_json:
        data = request.get_json() or {}
        scenario_id = (data.get("scenario_id") or "").strip()
        title = (data.get("title") or "").strip()
        description = (data.get("description") or "").strip()
        remediation_details = (data.get("remediation_details") or "").strip()
        finding_id_raw = data.get("finding_result_id")
        assigned_id_raw = data.get("assigned_user_id")
    else:
        scenario_id = (request.form.get("scenario_id") or "").strip()
        title = (request.form.get("title") or "").strip()
        description = (request.form.get("description") or "").strip()
        remediation_details = (request.form.get("remediation_details") or "").strip()
        finding_id_raw = request.form.get("finding_result_id")
        assigned_id_raw = request.form.get("assigned_user_id")

    if not scenario_id or not title:
        if wants_json_response():
            return jsonify({"error": "Scenario ID and Title are required fields."}), 400
        flash("Scenario ID and Title are required.", "danger")
        return redirect(url_for("remediations.new_remediation"))

    scenario = get_scenario(scenario_id)
    if not scenario:
        if wants_json_response():
            return jsonify({"error": f"Scenario '{scenario_id}' is not registered."}), 400
        flash(f"Scenario '{scenario_id}' is not registered.", "danger")
        return redirect(url_for("remediations.new_remediation"))

    finding_id = int(finding_id_raw) if finding_id_raw else None
    assigned_id = int(assigned_id_raw) if assigned_id_raw else None
    original_assessment_id = None

    if finding_id:
        finding = db.session.get(TestResult, finding_id)
        if finding:
            original_assessment_id = finding.assessment_id
            if finding.scenario_id != scenario_id:
                if wants_json_response():
                    return jsonify(
                        {"error": "Selected finding does not match specified scenario ID."}
                    ), 400
                flash("Selected finding does not match specified scenario ID.", "danger")
                return redirect(url_for("remediations.new_remediation"))

    now = datetime.now(UTC)
    remediation = Remediation(
        scenario_id=scenario_id,
        title=title,
        description=description,
        remediation_details=remediation_details,
        status=RemediationStatus.OPEN.value,
        verification_status=VerificationOutcome.UNVERIFIED.value,
        finding_result_id=finding_id,
        original_assessment_id=original_assessment_id,
        assigned_user_id=assigned_id,
        created_by_user_id=user.id,
        created_at=now,
        updated_at=now,
    )
    db.session.add(remediation)
    db.session.flush()

    audit = RemediationAuditEvent(
        remediation_id=remediation.id,
        event_type=AuditEventType.REMEDIATION_CREATED.value,
        actor_id=user.id,
        old_status=None,
        new_status=RemediationStatus.OPEN.value,
        details=f"Remediation #{remediation.id} created for scenario '{scenario_id}' by {user.email}.",
    )
    db.session.add(audit)
    db.session.commit()

    if wants_json_response():
        return jsonify(remediation.to_dict()), 201

    flash(f"Remediation #{remediation.id} created successfully.", "success")
    return redirect(url_for("remediations.detail", remediation_id=remediation.id))


@remediations_bp.route("/<int:remediation_id>", methods=["GET"])
@role_required(Role.SECURITY_ANALYST, Role.ADMIN)
def detail(remediation_id: int):
    """View detailed remediation workflow record, verification status, and audit trail."""
    remediation = db.session.get(Remediation, remediation_id)
    if not remediation:
        abort(404, description="Remediation record not found.")

    scenario = get_scenario(remediation.scenario_id)
    targets = LabTarget.query.filter_by(is_authorized=True).all()
    comparison = ComparisonService.compare_remediation(remediation)

    if wants_json_response():
        data = remediation.to_dict()
        data["audit_events"] = [e.to_dict() for e in remediation.audit_events]
        data["comparison"] = comparison
        return jsonify(data)

    return render_template(
        "remediations/detail.html",
        remediation=remediation,
        scenario=scenario,
        targets=targets,
        comparison=comparison,
    )


@remediations_bp.route("/<int:remediation_id>/status", methods=["POST"])
@role_required(Role.SECURITY_ANALYST, Role.ADMIN)
def update_status(remediation_id: int):
    """Update remediation workflow status with strict prohibition of manual VERIFIED transition."""
    user = get_current_user()

    if request.is_json:
        data = request.get_json() or {}
        new_status = data.get("status")
        note = data.get("note")
    else:
        new_status = request.form.get("status")
        note = request.form.get("note")

    if not new_status:
        if wants_json_response():
            return jsonify({"error": "Status is required."}), 400
        flash("Status is required.", "danger")
        return redirect(url_for("remediations.detail", remediation_id=remediation_id))

    try:
        remediation = VerificationService.update_workflow_status(
            remediation_id=remediation_id,
            new_status=new_status,
            actor=user,
            note=note,
        )
        if wants_json_response():
            return jsonify(remediation.to_dict())

        flash(f"Workflow status updated to '{new_status}'.", "success")
        return redirect(url_for("remediations.detail", remediation_id=remediation_id))

    except ValueError as exc:
        if wants_json_response():
            return jsonify({"error": str(exc)}), 400
        flash(str(exc), "danger")
        return redirect(url_for("remediations.detail", remediation_id=remediation_id))
    except AuthorizationError as exc:
        if wants_json_response():
            return jsonify({"error": str(exc)}), 403
        flash(str(exc), "danger")
        return redirect(url_for("remediations.detail", remediation_id=remediation_id))


@remediations_bp.route("/<int:remediation_id>/verify", methods=["POST"])
@role_required(Role.SECURITY_ANALYST, Role.ADMIN)
def verify(remediation_id: int):
    """Run automated defensive verification and regression tests against the secure lab target."""
    user = get_current_user()

    if request.is_json:
        data = request.get_json() or {}
        raw_target_id = data.get("target_id")
    else:
        raw_target_id = request.form.get("target_id")

    target_id = int(raw_target_id) if raw_target_id else None

    try:
        remediation, outcome, evidence = VerificationService.verify_remediation(
            remediation_id=remediation_id,
            actor=user,
            target_id=target_id,
        )

        if wants_json_response():
            return jsonify(
                {
                    "remediation": remediation.to_dict(),
                    "verification_outcome": outcome.value,
                    "evidence_sha256": remediation.evidence_sha256,
                    "evidence": evidence,
                }
            )

        if outcome == VerificationOutcome.VERIFIED:
            flash(
                f"Remediation #{remediation.id} VERIFIED successfully. All defensive checks passed.",
                "success",
            )
        else:
            flash(
                f"Defensive verification {outcome.value}. One or more checks failed; remediation marked REOPENED.",
                "warning",
            )

        return redirect(url_for("remediations.detail", remediation_id=remediation_id))

    except (AuthorizationError, ValueError) as exc:
        logger.warning(f"Verification rejected: {exc}")
        if wants_json_response():
            return jsonify({"error": str(exc)}), 400
        flash(str(exc), "danger")
        return redirect(url_for("remediations.detail", remediation_id=remediation_id))
    except Exception as exc:
        logger.exception(f"Unexpected error during verification: {exc}")
        if wants_json_response():
            return jsonify({"error": "An unexpected error occurred during verification."}), 500
        flash("An unexpected error occurred during verification.", "danger")
        return redirect(url_for("remediations.detail", remediation_id=remediation_id))


@remediations_bp.route("/<int:remediation_id>/compare", methods=["GET"])
@role_required(Role.SECURITY_ANALYST, Role.ADMIN)
def compare(remediation_id: int):
    """View dedicated before-and-after finding comparison and defensive delta."""
    remediation = db.session.get(Remediation, remediation_id)
    if not remediation:
        abort(404, description="Remediation record not found.")

    comparison = ComparisonService.compare_remediation(remediation)

    if wants_json_response():
        return jsonify(comparison)

    return render_template(
        "remediations/compare.html", remediation=remediation, comparison=comparison
    )
