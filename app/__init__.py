"""Application factory module for Vulnerability Assessment and Defense Lab (VADL)."""

from typing import Any

from flask import Flask, jsonify, render_template, request
from werkzeug.exceptions import HTTPException

from app.cli import register_cli_commands
from app.config import get_config
from app.extensions import db, migrate
from app.logging_config import setup_logging
from app.models.user import User as _User  # noqa: F401
from app.routes import (
    admin_bp,
    assessments_bp,
    auth_bp,
    dashboard_bp,
    health_bp,
    lab_secure_bp,
    lab_vulnerable_bp,
    profile_bp,
    remediations_bp,
    reports_bp,
    scans_bp,
)
from app.security import get_current_user, init_csrf


def create_app(config_name: str | None = None) -> Flask:
    """Flask application factory.

    Initializes configuration, extensions, logging, CSRF protection, blueprints, and error handlers.
    """
    app = Flask(__name__)

    # Load and apply configuration
    config_class = get_config(config_name)
    app.config.from_object(config_class)

    # Initialize structured, redacted logging
    setup_logging(app.config.get("LOG_LEVEL", "INFO"))
    app.logger.info(
        "Initializing VADL application in '%s' mode.",
        app.config.get("ENV", config_name or "default"),
    )

    # Initialize database and migration extensions
    db.init_app(app)
    migrate.init_app(app, db)

    # Initialize CSRF protection
    init_csrf(app)

    # Inject auth and lab state into all Jinja templates automatically
    @app.context_processor
    def inject_auth_context():
        return {
            "current_user": get_current_user(),
            "vulnerable_lab_enabled": app.config.get("ENABLE_VULNERABLE_LAB", False),
        }

    # Register blueprints
    app.register_blueprint(health_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(profile_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(assessments_bp)
    app.register_blueprint(lab_vulnerable_bp)
    app.register_blueprint(lab_secure_bp)
    app.register_blueprint(remediations_bp)
    app.register_blueprint(scans_bp)
    app.register_blueprint(reports_bp)

    # Register CLI commands
    register_cli_commands(app)

    # Register HTTP security response headers
    @app.after_request
    def set_security_headers(response):
        # Exclude lab header endpoints from being overwritten by default security headers
        if request.path in ("/lab/vulnerable/headers", "/lab/secure/headers"):
            return response
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "script-src 'self'; "
            "img-src 'self' data:; "
            "object-src 'none'; "
            "base-uri 'self';"
        )
        return response

    # Register error handlers
    register_error_handlers(app)

    return app


def register_error_handlers(app: Flask) -> None:
    """Register centralized, safe error handlers that never expose stack traces."""

    @app.errorhandler(400)
    def handle_bad_request(error: Any):
        description = getattr(error, "description", "Bad Request")
        if request.path.startswith(("/health", "/ready", "/api/")) or request.is_json:
            return jsonify({"error": description}), 400
        return render_template("errors/500.html", message=description), 400

    @app.errorhandler(403)
    def handle_forbidden(error: Any):
        description = getattr(
            error, "description", "Forbidden: You do not possess the required permissions."
        )
        if request.path.startswith(("/health", "/ready", "/api/")) or request.is_json:
            return jsonify({"error": description}), 403
        return render_template("errors/403.html", message=description), 403

    @app.errorhandler(404)
    def handle_not_found(error: Any):
        if request.path.startswith(("/health", "/ready", "/api/")) or request.is_json:
            return jsonify({"error": "Resource not found"}), 404
        return render_template("errors/404.html"), 404

    @app.errorhandler(413)
    def handle_payload_too_large(error: Any):
        if request.is_json:
            return jsonify({"error": "Request payload exceeds allowed limit"}), 413
        return render_template("errors/500.html", message="Request payload too large."), 413

    @app.errorhandler(429)
    def handle_rate_limit(error: Any):
        description = getattr(error, "description", "Too Many Requests")
        if request.is_json:
            return jsonify({"error": description}), 429
        return render_template("errors/500.html", message=description), 429

    @app.errorhandler(Exception)
    def handle_exception(error: Exception):
        # Distinguish standard HTTPExceptions (like abort(403)) from unhandled server exceptions
        if isinstance(error, HTTPException):
            code = error.code or 500
            if request.is_json:
                return jsonify({"error": error.description}), code
            if code == 403:
                return render_template("errors/403.html", message=error.description), 403
            if code == 404:
                return render_template("errors/404.html"), 404
            return render_template("errors/500.html", message=error.description), code

        # Log internal error without exposing tracebacks to end users
        app.logger.error("Unhandled internal exception: %s", type(error).__name__)

        if request.is_json:
            return jsonify({"error": "An internal server error occurred"}), 500
        return render_template("errors/500.html", message="An internal server error occurred."), 500
