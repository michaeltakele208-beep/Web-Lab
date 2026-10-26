"""Structured logging configuration for VADL.

Ensures log output is sanitized to prevent leakage of credentials, tokens,
cookies, authorization headers, and secrets.
"""

import logging
import re
import sys

# Regular expressions targeting sensitive patterns in logs
SENSITIVE_PATTERNS = [
    (re.compile(r"(password['\"]?\s*[:=]\s*['\"]?)([^'\",\s]+)", re.IGNORECASE), r"\1[REDACTED]"),
    (re.compile(r"(secret['\"]?\s*[:=]\s*['\"]?)([^'\",\s]+)", re.IGNORECASE), r"\1[REDACTED]"),
    (re.compile(r"(token['\"]?\s*[:=]\s*['\"]?)([^'\",\s]+)", re.IGNORECASE), r"\1[REDACTED]"),
    (
        re.compile(r"(api[_-]?key['\"]?\s*[:=]\s*['\"]?)([^'\",\s]+)", re.IGNORECASE),
        r"\1[REDACTED]",
    ),
    (re.compile(r"(Authorization\s*[:=]\s*Bearer\s+)(\S+)", re.IGNORECASE), r"\1[REDACTED]"),
    (re.compile(r"(Cookie\s*[:=]\s*)([^\r\n]+)", re.IGNORECASE), r"\1[REDACTED]"),
    (re.compile(r"(session\s*=\s*)([^;\s]+)", re.IGNORECASE), r"\1[REDACTED]"),
]


class RedactingFormatter(logging.Formatter):
    """Custom log formatter that scrubs sensitive data before output."""

    def format(self, record: logging.LogRecord) -> str:
        message = super().format(record)
        for pattern, replacement in SENSITIVE_PATTERNS:
            message = pattern.sub(replacement, message)
        return message


def setup_logging(log_level: str = "INFO") -> None:
    """Configure structured, sanitized root logging."""
    level = getattr(logging, log_level.upper(), logging.INFO)

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(level)

    formatter = RedactingFormatter(
        fmt="%(asctime)s [%(levelname)s] [%(name)s]: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Avoid duplicate handlers during testing or re-initialization
    root_logger.handlers.clear()
    root_logger.addHandler(handler)
