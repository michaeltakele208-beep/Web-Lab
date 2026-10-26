"""Application configuration module.

Provides explicit, environment-isolated configurations for development,
testing, and production environments.
"""

import os
from datetime import timedelta
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
INSTANCE_DIR = BASE_DIR / "instance"


class Config:
    """Base configuration with safe default values."""

    # Cryptographic secret key
    SECRET_KEY = os.environ.get("SECRET_KEY", "vadl-default-insecure-dev-key")

    # Database configuration
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL",
        f"sqlite:///{INSTANCE_DIR / 'vadl_dev.db'}",
    )

    # Request limits (1MB default payload limit for DoS mitigation)
    MAX_CONTENT_LENGTH = int(os.environ.get("MAX_CONTENT_LENGTH", 1 * 1024 * 1024))

    # Session configuration & cookie hardening
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = False  # Set to True in ProductionConfig for HTTPS
    PERMANENT_SESSION_LIFETIME = timedelta(
        seconds=int(os.environ.get("SESSION_LIFETIME_SECONDS", 7200))
    )

    # CSRF protection toggle (enabled by default)
    CSRF_ENABLED = True

    # Login rate limiting: max 5 attempts per 60 seconds by default
    LOGIN_RATE_LIMIT_MAX_ATTEMPTS = int(os.environ.get("LOGIN_RATE_LIMIT_MAX_ATTEMPTS", 5))
    LOGIN_RATE_LIMIT_WINDOW_SECONDS = int(os.environ.get("LOGIN_RATE_LIMIT_WINDOW_SECONDS", 60))

    # Password policy parameters
    PASSWORD_MIN_LENGTH = int(os.environ.get("PASSWORD_MIN_LENGTH", 10))

    # Security settings
    DEBUG = False
    TESTING = False

    # Vulnerable training lab toggle (strictly development/testing only)
    ENABLE_VULNERABLE_LAB = False

    # Phase 4: Offensive Testing Engine Parameters
    MAX_SCENARIOS_PER_ASSESSMENT = int(os.environ.get("MAX_SCENARIOS_PER_ASSESSMENT", 10))
    TEST_TIMEOUT_SECONDS = int(os.environ.get("TEST_TIMEOUT_SECONDS", 5))
    MAX_ASSESSMENT_DURATION_SECONDS = int(os.environ.get("MAX_ASSESSMENT_DURATION_SECONDS", 60))
    MAX_EVIDENCE_BYTES = int(os.environ.get("MAX_EVIDENCE_BYTES", 4096))

    # Phase 6: Automated Security Scanner Parameters
    SCAN_TIMEOUT_SECONDS = int(os.environ.get("SCAN_TIMEOUT_SECONDS", 120))
    MAX_REPORT_BYTES = int(os.environ.get("MAX_REPORT_BYTES", 1048576))  # 1 MB report limit

    # Server binding defaults
    HOST = os.environ.get("HOST", "127.0.0.1")
    PORT = int(os.environ.get("PORT", 5000))

    # Logging level
    LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")

    @classmethod
    def validate(cls) -> None:
        """Validate configuration settings at startup."""
        pass


class DevelopmentConfig(Config):
    """Configuration for local development."""

    DEBUG = True
    LOG_LEVEL = os.environ.get("LOG_LEVEL", "DEBUG")
    # Vulnerable lab mode enabled by default in local development for seamless demonstration
    ENABLE_VULNERABLE_LAB = os.environ.get("VADL_ENABLE_VULNERABLE_LAB", "true").lower() in (
        "true",
        "1",
    )


class TestingConfig(Config):
    """Configuration for automated test execution."""

    TESTING = True
    DEBUG = False
    # Use isolated in-memory SQLite database for deterministic tests
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SECRET_KEY = os.environ.get("TEST_SECRET_KEY", "test-secret-key-only-for-automated-tests")
    LOG_LEVEL = "WARNING"
    # Keep rate limits configurable and predictable in testing
    LOGIN_RATE_LIMIT_MAX_ATTEMPTS = 5
    LOGIN_RATE_LIMIT_WINDOW_SECONDS = 60
    # Enable lab in testing so automated scenario verifications can execute
    ENABLE_VULNERABLE_LAB = True


class ProductionConfig(Config):
    """Configuration for hardened production environments."""

    DEBUG = False
    TESTING = False
    # Enforce Secure flag on cookies in production HTTPS environments
    SESSION_COOKIE_SECURE = True
    # Vulnerable lab mode is unconditionally forbidden in production
    ENABLE_VULNERABLE_LAB = False

    @classmethod
    def validate(cls) -> None:
        """Validate critical production security requirements."""
        # Refuse startup if vulnerable mode is requested in production
        vulnerable_requested = os.environ.get("VADL_ENABLE_VULNERABLE_LAB", "false").lower() in (
            "true",
            "1",
        )
        if vulnerable_requested or getattr(cls, "ENABLE_VULNERABLE_LAB", False):
            raise ValueError(
                "CRITICAL SECURITY VIOLATION: Vulnerable lab mode (VADL_ENABLE_VULNERABLE_LAB) "
                "cannot be enabled under production configuration."
            )

        secret = os.environ.get("SECRET_KEY")
        insecure_keys = {
            None,
            "",
            "vadl-default-insecure-dev-key",
            "dev-only-insecure-secret-key-change-in-production",
            "changeme",
            "secret",
        }
        if secret in insecure_keys or len(str(secret)) < 32:
            raise ValueError(
                "CRITICAL SECURITY FAILURE: SECRET_KEY must be set via environment variable "
                "to a secure random string of at least 32 characters in production."
            )


config_by_name = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
}


def get_config(config_name: str | None = None) -> type[Config]:
    """Retrieve the appropriate configuration class based on name or environment variable."""
    if not config_name:
        config_name = os.environ.get("FLASK_CONFIG", "development").lower()

    if config_name not in config_by_name:
        raise ValueError(
            f"Unknown configuration environment: '{config_name}'. "
            f"Supported options: {list(config_by_name.keys())}"
        )

    selected_config = config_by_name[config_name]
    selected_config.validate()
    return selected_config
