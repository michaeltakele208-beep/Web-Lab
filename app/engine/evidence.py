"""Evidence collection, redaction, and sanitization for the VADL offensive testing engine."""

import json
import re
from typing import Any

# Regular expression patterns for scrubbing sensitive credentials from stored evidence
SENSITIVE_PATTERNS = [
    (re.compile(r"(csrf_token=)[a-zA-Z0-9_\-]+", re.IGNORECASE), r"\1[REDACTED_CSRF_TOKEN]"),
    (re.compile(r'("csrf_token"\s*:\s*")[^"]+(")', re.IGNORECASE), r"\1[REDACTED_CSRF_TOKEN]\2"),
    (re.compile(r"(password=)[^&]+", re.IGNORECASE), r"\1[REDACTED_PASSWORD]"),
    (re.compile(r'("password"\s*:\s*")[^"]+(")', re.IGNORECASE), r"\1[REDACTED_PASSWORD]\2"),
    (re.compile(r"(session=)[a-zA-Z0-9_\.\-]+", re.IGNORECASE), r"\1[REDACTED_SESSION]"),
    (re.compile(r"(Authorization:\s*Bearer\s+)[^\r\n]+", re.IGNORECASE), r"\1[REDACTED_TOKEN]"),
    (re.compile(r"(Authorization:\s*Basic\s+)[^\r\n]+", re.IGNORECASE), r"\1[REDACTED_CREDS]"),
    (re.compile(r"(Set-Cookie:\s*session=)[^;]+", re.IGNORECASE), r"\1[REDACTED_SESSION]"),
]


def sanitize_text(text: str | None) -> str:
    """Scrub sensitive credentials, tokens, and cookies from evidence text."""
    if not text:
        return ""
    sanitized = text
    for pattern, replacement in SENSITIVE_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)
    return sanitized


def truncate_evidence(text: str, max_bytes: int = 4096) -> str:
    """Ensure evidence does not exceed maximum storage size constraints."""
    if not text:
        return ""
    encoded = text.encode("utf-8")
    if len(encoded) <= max_bytes:
        return text

    # Truncate at character boundary within max_bytes limit
    truncated = encoded[:max_bytes].decode("utf-8", errors="ignore")
    return truncated + "\n... [TRUNCATED: Exceeded evidence size limit]"


def build_evidence(
    *,
    scenario_id: str,
    test_identifier: str,
    target_edition: str,
    request_method: str,
    request_url: str,
    request_payload: Any = None,
    response_status: int | None = None,
    response_headers: dict[str, str] | None = None,
    response_body_snippet: str | None = None,
    expected_behavior: str,
    observed_behavior: str,
    rationale: str,
    max_bytes: int = 4096,
) -> str:
    """Construct a structured, sanitized evidence artifact."""
    raw_evidence = {
        "scenario_id": scenario_id,
        "test_identifier": test_identifier,
        "target_edition": target_edition,
        "request": {
            "method": request_method,
            "url": request_url,
            "payload": request_payload,
        },
        "response": {
            "status_code": response_status,
            "headers": response_headers or {},
            "body_snippet": response_body_snippet or "",
        },
        "evaluation": {
            "expected_behavior": expected_behavior,
            "observed_behavior": observed_behavior,
            "rationale": rationale,
        },
    }

    serialized = json.dumps(raw_evidence, indent=2)
    sanitized = sanitize_text(serialized)
    return truncate_evidence(sanitized, max_bytes=max_bytes)
