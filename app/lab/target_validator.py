"""Target allowlist validation and SSRF mitigation controls for VADL."""

from urllib.parse import urlsplit

# Strictly permit only designated local and containerized lab hostnames
ALLOWED_LAB_HOSTNAMES = frozenset(
    {
        "127.0.0.1",
        "localhost",
        "::1",
        "vadl-app",
        "vadl-core-app",
        "vadl-vulnerable-app",
        "vadl-target",
        "vadl-isolated-target",
    }
)

ALLOWED_SCHEMES = frozenset({"http", "https"})


def validate_lab_target_url(raw_url: str | None) -> tuple[bool, str]:
    """Validate that a target URL strictly matches approved internal laboratory hosts.

    Security constraints:
    - Rejects unexpected schemes (file://, gopher://, ftp://, javascript://).
    - Rejects cloud metadata addresses (169.254.169.254).
    - Rejects external public domains and arbitrary internet targets.
    - Operates purely through lexical parsing without making any outbound network connections.
    """
    if not raw_url or not isinstance(raw_url, str):
        return False, "Target URL must be a non-empty string."

    stripped = raw_url.strip()
    if len(stripped) > 255:
        return False, "Target URL cannot exceed 255 characters."

    try:
        parsed = urlsplit(stripped)
    except Exception:
        return False, "Malformed target URL structure."

    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        return (
            False,
            f"Invalid URL scheme '{parsed.scheme}'. Only HTTP and HTTPS are permitted for lab targets.",
        )

    hostname = (parsed.hostname or "").lower()
    if not hostname:
        return False, "Target URL must include a valid hostname."

    # Prevent cloud metadata and loopback bypass tricks
    if hostname == "169.254.169.254" or hostname.startswith("169.254."):
        return False, "Cloud metadata services are strictly prohibited as lab targets."

    # Validate against strict lab hostname allowlist
    if hostname not in ALLOWED_LAB_HOSTNAMES:
        return (
            False,
            f"Target host '{hostname}' is not in the approved laboratory network allowlist. "
            "Arbitrary internet destinations and non-lab hosts are strictly rejected.",
        )

    # Validate port if explicitly declared
    if parsed.port is not None and not (1 <= parsed.port <= 65535):
        return False, "Port number must be between 1 and 65535."

    return True, ""
