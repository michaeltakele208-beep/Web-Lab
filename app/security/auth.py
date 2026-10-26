"""Authentication, authorization, and input validation utilities."""

import re
import secrets
from functools import wraps
from urllib.parse import urlsplit

from flask import abort, current_app, g, jsonify, redirect, request, session, url_for

from app.extensions import db
from app.models.user import User


def get_current_user() -> User | None:
    """Retrieve the currently authenticated user based on session identity."""
    if hasattr(g, "current_user"):
        return g.current_user

    user_id = session.get("user_id")
    if not user_id:
        g.current_user = None
        return None

    user = db.session.get(User, user_id)
    if not user or not user.is_active_account:
        # Inactive or deleted user session must be cleared
        session.clear()
        g.current_user = None
        return None

    g.current_user = user
    return user


def login_user(user: User) -> None:
    """Establish an authenticated session with session identifier renewal (fixation mitigation)."""
    # Renew session identifier and state
    session.clear()
    session["user_id"] = user.id
    session["user_email"] = user.email
    session["user_role"] = user.role
    session.permanent = True
    # Issue fresh CSRF token for the authenticated session
    session["_csrf_token"] = secrets.token_hex(32)
    g.current_user = user


def logout_user() -> None:
    """Invalidate and purge the current authenticated session."""
    session.clear()
    g.current_user = None


def login_required(f):
    """Decorator requiring active user authentication."""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = get_current_user()
        wants_json = (
            request.is_json
            or request.path.startswith("/api/")
            or (request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html)
        )
        if not user:
            if wants_json:
                return jsonify({"error": "Authentication required"}), 401
            return redirect(url_for("auth.login", next=request.path))
        if not user.is_active_account:
            logout_user()
            abort(403, description="Account has been disabled.")
        return f(*args, **kwargs)

    return decorated_function


def role_required(*roles: str):
    """Decorator restricting route access to users holding at least one specified role."""

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user = get_current_user()
            wants_json = (
                request.is_json
                or request.path.startswith("/api/")
                or (
                    request.accept_mimetypes.accept_json
                    and not request.accept_mimetypes.accept_html
                )
            )
            if not user:
                if wants_json:
                    return jsonify({"error": "Authentication required"}), 401
                return redirect(url_for("auth.login", next=request.path))
            if not user.is_active_account:
                logout_user()
                abort(403, description="Account has been disabled.")
            if not user.has_role(*roles):
                if wants_json:
                    return jsonify({"error": "Forbidden: insufficient permissions"}), 403
                abort(403, description="Forbidden: You do not possess the required permissions.")
            return f(*args, **kwargs)

        return decorated_function

    return decorator


def normalize_email(email: str | None) -> str:
    """Strip whitespace and lowercase email strings for canonical normalization."""
    if not email:
        return ""
    return email.strip().lower()


def validate_email(email: str) -> tuple[bool, str]:
    """Validate email format and length constraints."""
    if not email or len(email) > 255:
        return False, "Email address must be between 3 and 255 characters."
    pattern = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
    if not re.match(pattern, email):
        return False, "Please enter a valid email address format."
    return True, ""


def validate_display_name(name: str) -> tuple[bool, str]:
    """Validate user display name."""
    if not name or len(name.strip()) < 2 or len(name.strip()) > 50:
        return False, "Display name must be between 2 and 50 characters."
    return True, ""


def validate_password(password: str) -> tuple[bool, str]:
    """Enforce the laboratory password policy.

    Requirements:
    - Minimum length (default 10 characters).
    - At least one uppercase letter.
    - At least one lowercase letter.
    - At least one digit.
    - At least one special symbol.
    """
    min_length = current_app.config.get("PASSWORD_MIN_LENGTH", 10)
    if not password or len(password) < min_length:
        return False, f"Password must be at least {min_length} characters in length."
    if not re.search(r"[A-Z]", password):
        return False, "Password must include at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must include at least one lowercase letter."
    if not re.search(r"\d", password):
        return False, "Password must include at least one number."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>\-_=+[\]\\/]", password):
        return False, "Password must include at least one special character."
    return True, ""


def is_safe_redirect(target_url: str | None) -> bool:
    """Validate that redirect destination is strictly local, mitigating open redirect attacks."""
    if not target_url:
        return False
    # Reject absolute URLs, scheme-relative URLs (//example.com), and carriage returns
    if target_url.startswith(("//", "\\\\")) or "\r" in target_url or "\n" in target_url:
        return False
    parsed = urlsplit(target_url)
    return parsed.scheme == "" and parsed.netloc == "" and target_url.startswith("/")
