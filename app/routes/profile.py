"""User profile view and update endpoints."""

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
from app.models.user import User
from app.security import (
    get_current_user,
    login_required,
    validate_display_name,
)

profile_bp = Blueprint("profile", __name__)
logger = logging.getLogger(__name__)


@profile_bp.route("/profile", methods=["GET", "POST"])
@login_required
def view_profile():
    """Current authenticated user profile view and display name modification."""
    user = get_current_user()

    if request.method == "POST":
        # Only allow updating display name; ignore/reject any role or status changes
        new_display_name = (request.form.get("display_name") or "").strip()

        valid, error_msg = validate_display_name(new_display_name)
        if not valid:
            flash(error_msg, "danger")
            return render_template("profile.html", user=user), 400

        user.display_name = new_display_name
        db.session.commit()
        logger.info("User display name updated successfully.")
        flash("Profile updated successfully.", "success")
        return redirect(url_for("profile.view_profile"))

    return render_template("profile.html", user=user)


@profile_bp.route("/users/<int:user_id>", methods=["GET"])
@login_required
def get_user_profile(user_id: int):
    """Enforce authorization boundary preventing horizontal privilege escalation across user profiles."""
    current_user = get_current_user()

    # Horizontal access control: non-administrators may only access their own profile
    if current_user.id != user_id and not current_user.is_admin:
        logger.warning(
            "Unauthorized profile access attempt by user %s targeting user %s.",
            current_user.id,
            user_id,
        )
        abort(403, description="Forbidden: You are not authorized to view another user's profile.")

    target_user = db.session.get(User, user_id)
    if not target_user:
        abort(404)
    return render_template("profile.html", user=target_user, is_admin_view=current_user.is_admin)
