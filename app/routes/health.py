"""Health and readiness monitoring endpoints.

Kept strictly minimal to prevent leaking internal infrastructure details.
"""

import logging

from flask import Blueprint, jsonify
from sqlalchemy import text

from app.extensions import db

health_bp = Blueprint("health", __name__)
logger = logging.getLogger(__name__)


@health_bp.route("/health", methods=["GET"])
def health_check():
    """Minimal liveness probe.

    Returns HTTP 200 with minimal status if the web server process is responsive.
    """
    return jsonify({"status": "ok"}), 200


@health_bp.route("/ready", methods=["GET"])
def readiness_check():
    """Readiness probe checking critical dependency availability.

    Verifies database connectivity. Returns HTTP 200 if ready to serve traffic,
    or HTTP 503 if required dependencies are unreachable.
    """
    try:
        # Check database responsiveness with a lightweight ping
        db.session.execute(text("SELECT 1"))
        return jsonify({"status": "ready"}), 200
    except Exception as exc:
        # Log sanitized error internally without exposing details to the caller
        logger.error(
            "Readiness probe failed during database connectivity check: %s", type(exc).__name__
        )
        return jsonify({"status": "unavailable"}), 503
