"""Security utilities package for VADL."""

from app.security.auth import (
    get_current_user,
    is_safe_redirect,
    login_required,
    login_user,
    logout_user,
    normalize_email,
    role_required,
    validate_display_name,
    validate_email,
    validate_password,
)
from app.security.csrf import generate_csrf_token, init_csrf
from app.security.rate_limiter import (
    clear_all_rate_limits,
    get_client_ip,
    is_rate_limited,
    record_attempt,
    reset_attempts,
)

__all__ = [
    "clear_all_rate_limits",
    "generate_csrf_token",
    "get_client_ip",
    "get_current_user",
    "init_csrf",
    "is_rate_limited",
    "is_safe_redirect",
    "login_required",
    "login_user",
    "logout_user",
    "normalize_email",
    "record_attempt",
    "reset_attempts",
    "role_required",
    "validate_display_name",
    "validate_email",
    "validate_password",
]
