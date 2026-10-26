"""Security assessment routes and Offensive Testing Engine API (Phase 4)."""

import logging

from flask import Blueprint, abort, flash, jsonify, redirect, render_template, request, url_for

from app.engine.orchestrator import AssessmentOrchestrator, DuplicateAssessmentError
from app.engine.target_guard import AuthorizationError
from app.extensions import db
from app.lab.registry import get_all_scenarios, get_scenario
from app.models.assessment import Assessment, TestResult
from app.models.lab import LabTarget
from app.models.user import Role
from app.security import get_current_user, role_required

logger = logging.getLogger("vadl.routes.assessments")

assessments_bp = Blueprint("assessments", __name__, url_prefix="/assessments")


def wants_json_response() -> bool:
    """Check if the requesting client explicitly requests a JSON response."""
    return (
        request.is_json
        or request.path.startswith("/api/")
        or (request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html)
    )


@assessments_bp.route("", methods=["GET"])
@role_required(Role.SECURITY_ANALYST, Role.ADMIN)
def index():
    """Security assessment console displaying documented scenarios, authorized targets, and recent runs."""
    scenarios = get_all_scenarios()
    targets = LabTarget.query.filter_by(is_authorized=True).all()
    recent_assessments = Assessment.query.order_by(Assessment.created_at.desc()).limit(10).all()

    if wants_json_response():
        return jsonify(
            {
                "scenarios": [s.to_dict() for s in scenarios],
                "targets": [t.to_dict() for t in targets],
                "recent_assessments": [a.to_dict() for a in recent_assessments],
            }
        )

    return render_template(
        "assessments/index.html",
        scenarios=scenarios,
        targets=targets,
        recent_assessments=recent_assessments,
    )


@assessments_bp.route("/run", methods=["POST"])
@role_required(Role.SECURITY_ANALYST, Role.ADMIN)
def run_assessment():
    """Initiate and execute an offensive security assessment against an authorized lab target."""
    user = get_current_user()

    # Extract parameters from form or JSON
    if request.is_json:
        data = request.get_json() or {}
        raw_target_id = data.get("target_id")
        scenario_ids = data.get("scenarios", [])
        target_edition = data.get("target_edition", "both")
    else:
        raw_target_id = request.form.get("target_id")
        scenario_ids = request.form.getlist("scenarios")
        target_edition = request.form.get("target_edition", "both")

    try:
        target_id = int(raw_target_id)
    except (TypeError, ValueError):
        if wants_json_response():
            return jsonify({"error": "Invalid target_id specified. Must be an integer."}), 400
        flash("Invalid target specified. Please select a valid authorized target.", "danger")
        return redirect(url_for("assessments.index"))

    try:
        # Create and queue assessment (enforces target authorization, bounds, and duplicate check)
        assessment = AssessmentOrchestrator.create_assessment(
            user=user,
            target_id=target_id,
            scenario_ids=scenario_ids,
            target_edition=target_edition,
        )

        # Execute assessment synchronously in-process
        assessment = AssessmentOrchestrator.execute_assessment(assessment.id)

        if wants_json_response():
            return jsonify(assessment.to_dict()), 201

        flash(
            f"Assessment #{assessment.id} completed with status '{assessment.status}'. "
            f"{assessment.confirmed_vulnerabilities} vulnerabilities confirmed, {assessment.passed_checks} checks passed.",
            "success" if assessment.status == "completed" else "warning",
        )
        return redirect(url_for("assessments.detail", assessment_id=assessment.id))

    except AuthorizationError as exc:
        logger.warning(f"Assessment rejected at authorization boundary: {exc}")
        if wants_json_response():
            return jsonify({"error": exc.message, "reason": exc.reason}), 403
        flash(f"Authorization Error: {exc.message}", "danger")
        return redirect(url_for("assessments.index"))

    except DuplicateAssessmentError as exc:
        logger.info(f"Duplicate assessment rejected: {exc}")
        if wants_json_response():
            return jsonify({"error": str(exc)}), 409
        flash(str(exc), "warning")
        return redirect(url_for("assessments.index"))

    except Exception as exc:
        logger.exception(f"Unexpected error scheduling assessment: {exc}")
        if wants_json_response():
            return jsonify(
                {"error": "An unexpected error occurred while executing the assessment."}
            ), 500
        flash("An unexpected error occurred while initiating the assessment.", "danger")
        return redirect(url_for("assessments.index"))


@assessments_bp.route("/<int:assessment_id>", methods=["GET"])
@role_required(Role.SECURITY_ANALYST, Role.ADMIN)
def detail(assessment_id: int):
    """View assessment run status, test execution results, and metrics."""
    assessment = db.session.get(Assessment, assessment_id)
    if not assessment:
        abort(404, description="Assessment run not found.")

    if wants_json_response():
        data = assessment.to_dict()
        data["results"] = [r.to_dict() for r in assessment.results]
        return jsonify(data)

    return render_template("assessments/detail.html", assessment=assessment)


@assessments_bp.route("/<int:assessment_id>/results/<int:result_id>", methods=["GET"])
@role_required(Role.SECURITY_ANALYST, Role.ADMIN)
def result_detail(assessment_id: int, result_id: int):
    """Detailed forensic inspection of an individual test result and its sanitized evidence."""
    result = TestResult.query.filter_by(id=result_id, assessment_id=assessment_id).first_or_404()
    scenario = get_scenario(result.scenario_id)

    if wants_json_response():
        return jsonify(result.to_dict())

    return render_template("assessments/result_detail.html", result=result, scenario=scenario)


@assessments_bp.route("/<int:assessment_id>/cancel", methods=["POST"])
@role_required(Role.SECURITY_ANALYST, Role.ADMIN)
def cancel(assessment_id: int):
    """Cancel a queued or active assessment."""
    user = get_current_user()
    try:
        assessment = AssessmentOrchestrator.cancel_assessment(assessment_id, user)
        if wants_json_response():
            return jsonify(
                {
                    "message": f"Assessment #{assessment.id} has been cancelled.",
                    "status": assessment.status,
                }
            )
        flash(f"Assessment #{assessment.id} has been cancelled.", "info")
        return redirect(url_for("assessments.detail", assessment_id=assessment.id))
    except (AuthorizationError, ValueError) as exc:
        if wants_json_response():
            return jsonify({"error": str(exc)}), 400
        flash(str(exc), "danger")
        return redirect(url_for("assessments.detail", assessment_id=assessment_id))


@assessments_bp.route("/history", methods=["GET"])
@role_required(Role.SECURITY_ANALYST, Role.ADMIN)
def history():
    """Paginated audit history of past security assessments."""
    page = request.args.get("page", 1, type=int)
    status_filter = request.args.get("status")
    target_id_filter = request.args.get("target_id", type=int)

    query = Assessment.query.order_by(Assessment.created_at.desc())
    if status_filter:
        query = query.filter_by(status=status_filter)
    if target_id_filter:
        query = query.filter_by(target_id=target_id_filter)

    pagination = query.paginate(page=page, per_page=10, error_out=False)

    if wants_json_response():
        return jsonify(
            {
                "items": [a.to_dict() for a in pagination.items],
                "page": pagination.page,
                "pages": pagination.pages,
                "total": pagination.total,
            }
        )

    targets = LabTarget.query.all()
    return render_template(
        "assessments/history.html",
        pagination=pagination,
        targets=targets,
        status_filter=status_filter,
        target_id_filter=target_id_filter,
    )


@assessments_bp.route("/scenarios/<string:scenario_id>", methods=["GET"])
@role_required(Role.SECURITY_ANALYST, Role.ADMIN)
def scenario_detail(scenario_id: str):
    """Detailed scenario technical dossier for analysts and administrators."""
    scenario = get_scenario(scenario_id)
    if not scenario:
        abort(404, description="Scenario not found.")

    if wants_json_response():
        return jsonify(scenario.to_dict())

    return render_template("assessments/scenario_detail.html", scenario=scenario)
