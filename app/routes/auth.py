"""Authentication routes: registration, login, and logout."""

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
from app.models.user import Role, User, UserStatus
from app.security import (
    get_client_ip,
    get_current_user,
    is_rate_limited,
    is_safe_redirect,
    login_required,
    login_user,
    logout_user,
    normalize_email,
    record_attempt,
    reset_attempts,
    validate_display_name,
    validate_email,
    validate_password,
)

auth_bp = Blueprint("auth", __name__)
logger = logging.getLogger(__name__)


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    """User account self-registration endpoint."""
    if get_current_user():
        return redirect(url_for("dashboard.index"))

    if request.method == "POST":
        # Extract exclusively authorized user registration fields (prevent mass assignment)
        display_name = (request.form.get("display_name") or "").strip()
        raw_email = request.form.get("email") or ""
        password = request.form.get("password") or ""
        confirm_password = request.form.get("confirm_password") or ""

        # Validate display name
        valid_name, name_error = validate_display_name(display_name)
        if not valid_name:
            flash(name_error, "danger")
            return render_template(
                "auth/register.html", display_name=display_name, email=raw_email
            ), 400

        # Validate email
        email = normalize_email(raw_email)
        valid_email, email_error = validate_email(email)
        if not valid_email:
            flash(email_error, "danger")
            return render_template(
                "auth/register.html", display_name=display_name, email=raw_email
            ), 400

        # Check for duplicate normalized email
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash("An account associated with this email address already exists.", "danger")
            return render_template(
                "auth/register.html", display_name=display_name, email=raw_email
            ), 400

        # Validate password matching
        if password != confirm_password:
            flash("Passwords do not match. Please re-enter your password.", "danger")
            return render_template(
                "auth/register.html", display_name=display_name, email=raw_email
            ), 400

        # Validate password against laboratory security policy
        valid_pwd, pwd_error = validate_password(password)
        if not valid_pwd:
            flash(pwd_error, "danger")
            return render_template(
                "auth/register.html", display_name=display_name, email=raw_email
            ), 400

        # Security control: newly registered users ALWAYS receive ordinary 'user' role
        new_user = User(
            email=email,
            display_name=display_name,
            role=Role.USER,
            status=UserStatus.ACTIVE,
        )
        new_user.set_password(password)

        db.session.add(new_user)
        db.session.commit()
        logger.info("New user account registered successfully with ordinary role.")

        flash("Registration successful. Please log in with your credentials.", "success")
        return redirect(url_for("auth.login"))

    return render_template("auth/register.html")


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    """User authentication endpoint with rate limiting and generic failure feedback."""
    if get_current_user():
        return redirect(url_for("dashboard.index"))

    client_ip = get_client_ip()

    if request.method == "POST":
        # Check login rate limit
        if is_rate_limited(client_ip):
            logger.warning("Authentication rate limit exceeded for client.")
            abort(
                429,
                description="Too many failed login attempts. Please wait a minute before retrying.",
            )

        raw_email = request.form.get("email") or ""
        password = request.form.get("password") or ""
        next_target = request.form.get("next") or request.args.get("next")

        email = normalize_email(raw_email)
        user = User.query.filter_by(email=email).first()

        # Generic authentication failure: never disclose whether the email address exists
        if not user or not user.check_password(password):
            record_attempt(client_ip)
            logger.info("Failed authentication attempt.")
            flash("Invalid email or password.", "danger")
            return render_template("auth/login.html", email=raw_email, next=next_target), 401

        # Check account status
        if not user.is_active_account:
            record_attempt(client_ip)
            logger.warning("Authentication rejected: Account is disabled.")
            flash("Invalid email or password.", "danger")
            return render_template("auth/login.html", email=raw_email, next=next_target), 401

        # Successful authentication: reset rate limiting and establish session with renewal
        reset_attempts(client_ip)
        login_user(user)
        logger.info("User authenticated successfully.")

        flash(f"Welcome back, {user.display_name}!", "success")

        # Open redirect protection
        if is_safe_redirect(next_target):
            return redirect(next_target)
        return redirect(url_for("dashboard.index"))

    return render_template("auth/login.html", next=request.args.get("next"))


@auth_bp.route("/logout", methods=["GET", "POST"])
@login_required
def logout():
    """Terminate the authenticated session."""
    logout_user()
    logger.info("User logged out successfully.")
    flash("You have been logged out.", "info")
    return redirect(url_for("auth.login"))
