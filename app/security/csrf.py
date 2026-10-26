"""Cryptographic CSRF protection mechanism for state-changing browser requests."""

import hmac
import secrets

from flask import Flask, abort, current_app, request, session

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})


def generate_csrf_token() -> str:
    """Generate or retrieve a cryptographically random CSRF token bound to the current session."""
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)
    return session["_csrf_token"]


def init_csrf(app: Flask) -> None:
    """Initialize CSRF verification hook and template context processor."""

    # Expose csrf_token() helper to all Jinja templates
    @app.context_processor
    def inject_csrf_token():
        return {"csrf_token": generate_csrf_token}

    # Intercept all state-changing requests and verify CSRF token
    @app.before_request
    def verify_csrf():
        if request.method in SAFE_METHODS:
            return

        # Check configuration toggle
        if not current_app.config.get("CSRF_ENABLED", True):
            return

        # Probe endpoints (e.g. health checks) are GET only, but if testing or exempt:
        if request.path.startswith(("/health", "/ready")):
            return

        submitted_token = (
            request.form.get("csrf_token")
            or request.headers.get("X-CSRF-Token")
            or request.headers.get("X-CSRFToken")
            or (
                request.is_json
                and request.get_json(silent=True)
                and request.get_json(silent=True).get("csrf_token")
            )
        )
        session_token = session.get("_csrf_token")

        if not submitted_token or not session_token:
            abort(400, description="CSRF verification failed: Token is missing.")

        # Constant-time comparison prevents timing attacks
        if not hmac.compare_digest(str(submitted_token), str(session_token)):
            abort(400, description="CSRF verification failed: Token is invalid.")
