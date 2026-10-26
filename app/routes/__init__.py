"""Routes package for VADL."""

from app.routes.admin import admin_bp
from app.routes.assessments import assessments_bp
from app.routes.auth import auth_bp
from app.routes.dashboard import dashboard_bp
from app.routes.health import health_bp
from app.routes.lab_secure import lab_secure_bp
from app.routes.lab_vulnerable import lab_vulnerable_bp
from app.routes.profile import profile_bp
from app.routes.remediations import remediations_bp
from app.routes.reports import reports_bp
from app.routes.scans import scans_bp

__all__ = [
    "admin_bp",
    "assessments_bp",
    "auth_bp",
    "dashboard_bp",
    "health_bp",
    "lab_secure_bp",
    "lab_vulnerable_bp",
    "profile_bp",
    "remediations_bp",
    "reports_bp",
    "scans_bp",
]
