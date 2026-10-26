"""Administration console and user management endpoints."""

import logging

from flask import (
    Blueprint,
    abort,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)

from app.extensions import db
from app.lab.registry import get_all_scenarios
from app.lab.target_validator import validate_lab_target_url
from app.models.lab import LabTarget
from app.models.user import Role, User, UserStatus
from app.security import (
    get_current_user,
    role_required,
)

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")
logger = logging.getLogger(__name__)


@admin_bp.route("", methods=["GET"])
@role_required(Role.ADMIN)
def index():
    """Administrative overview and platform metrics."""
    total_users = User.query.count()
    active_users = User.query.filter_by(status=UserStatus.ACTIVE).count()
    disabled_users = User.query.filter_by(status=UserStatus.DISABLED).count()
    analyst_users = User.query.filter_by(role=Role.SECURITY_ANALYST).count()
    admin_users = User.query.filter_by(role=Role.ADMIN).count()

    stats = {
        "total": total_users,
        "active": active_users,
        "disabled": disabled_users,
        "analysts": analyst_users,
        "admins": admin_users,
    }
    return render_template("admin/dashboard.html", stats=stats)


@admin_bp.route("/users", methods=["GET"])
@role_required(Role.ADMIN)
def list_users():
    """Administrative user management listing."""
    users = User.query.order_by(User.id.asc()).all()
    return render_template(
        "admin/users.html",
        users=users,
        all_roles=Role.ALL_ROLES,
        all_statuses=UserStatus.ALL_STATUSES,
    )


@admin_bp.route("/users/<int:user_id>/role", methods=["POST"])
@role_required(Role.ADMIN)
def update_user_role(user_id: int):
    """Assign or modify user authorization role."""
    current_admin = get_current_user()
    target_user = db.session.get(User, user_id)
    if not target_user:
        abort(404)
    new_role = request.form.get("role")

    if new_role not in Role.ALL_ROLES:
        flash("Invalid role specified.", "danger")
        return redirect(url_for("admin.list_users"))

    # Security guard: administrators cannot demote their own active session account
    if target_user.id == current_admin.id and new_role != Role.ADMIN:
        flash(
            "Action prevented: You cannot remove the administrator role from your own account.",
            "warning",
        )
        return redirect(url_for("admin.list_users"))

    target_user.role = new_role
    db.session.commit()
    logger.info("Admin updated role for user %s to %s.", target_user.id, new_role)
    flash(f"Role for {target_user.display_name} updated to '{new_role}'.", "success")
    return redirect(url_for("admin.list_users"))


@admin_bp.route("/users/<int:user_id>/status", methods=["POST"])
@role_required(Role.ADMIN)
def update_user_status(user_id: int):
    """Enable or disable user account status."""
    current_admin = get_current_user()
    target_user = db.session.get(User, user_id)
    if not target_user:
        abort(404)
    new_status = request.form.get("status")

    if new_status not in UserStatus.ALL_STATUSES:
        flash("Invalid status specified.", "danger")
        return redirect(url_for("admin.list_users"))

    # Security guard: administrators cannot disable their own active account
    if target_user.id == current_admin.id and new_status == UserStatus.DISABLED:
        flash("Action prevented: You cannot disable your own administrator account.", "warning")
        return redirect(url_for("admin.list_users"))

    target_user.status = new_status
    db.session.commit()
    logger.info("Admin updated status for user %s to %s.", target_user.id, new_status)
    flash(f"Status for {target_user.display_name} updated to '{new_status}'.", "success")
    return redirect(url_for("admin.list_users"))


@admin_bp.route("/lab", methods=["GET"])
@role_required(Role.ADMIN)
def lab_console():
    """Administrative vulnerability lab configuration and target registry."""
    scenarios = get_all_scenarios()
    targets = LabTarget.query.order_by(LabTarget.id.asc()).all()
    return render_template(
        "admin/lab.html",
        scenarios=scenarios,
        targets=targets,
    )


@admin_bp.route("/lab/targets", methods=["POST"])
@role_required(Role.ADMIN)
def register_target():
    """Register an explicitly authorized laboratory target with strict validation."""
    name = (request.form.get("name") or "").strip()
    target_type = (request.form.get("target_type") or "internal_lab_edition").strip()
    environment_id = (request.form.get("environment_id") or "development").strip()
    base_url = (request.form.get("base_url") or "").strip()

    if not name or len(name) < 2 or len(name) > 100:
        flash("Target name must be between 2 and 100 characters.", "danger")
        return redirect(url_for("admin.lab_console"))

    # Strict SSRF & allowlist validation without external network calls
    valid, error_msg = validate_lab_target_url(base_url)
    if not valid:
        flash(f"Target registration rejected: {error_msg}", "danger")
        return redirect(url_for("admin.lab_console"))

    # Check for duplicate target URL
    existing = LabTarget.query.filter_by(base_url=base_url).first()
    if existing:
        flash("A target with this base URL is already registered.", "warning")
        return redirect(url_for("admin.lab_console"))

    current_admin = get_current_user()
    target = LabTarget(
        name=name,
        target_type=target_type,
        environment_id=environment_id,
        base_url=base_url,
        is_authorized=True,  # Administrator explicitly authorized upon registration
        registered_by_id=current_admin.id if current_admin else None,
    )
    db.session.add(target)
    db.session.commit()
    logger.info("Admin registered authorized lab target: %s (%s)", name, base_url)
    flash(f"Successfully registered and authorized target '{name}'.", "success")
    return redirect(url_for("admin.lab_console"))


@admin_bp.route("/lab/targets/<int:target_id>/toggle", methods=["POST"])
@role_required(Role.ADMIN)
def toggle_target_authorization(target_id: int):
    """Toggle target authorization status."""
    target = db.session.get(LabTarget, target_id)
    if not target:
        abort(404)

    target.is_authorized = not target.is_authorized
    db.session.commit()
    status_str = "authorized" if target.is_authorized else "revoked"
    logger.info("Admin toggled target %s authorization to %s.", target.id, status_str)
    flash(f"Target '{target.name}' authorization status updated to {status_str}.", "success")
    return redirect(url_for("admin.lab_console"))
