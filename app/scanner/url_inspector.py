"""Live URL Security Inspector and Header Analyzer.

Performs non-destructive passive security assessment of target web endpoints,
evaluating Transport Layer Security (TLS), HTTP security headers, cookie flags,
technology fingerprint leakage, and cross-origin controls.
"""

import hashlib
import logging
import re
from typing import Any
from urllib.parse import urlparse

import requests
from requests.exceptions import RequestException

from app.scanner.grader import grade_posture

logger = logging.getLogger("vadl.scanner.url_inspector")

DEFAULT_USER_AGENT = "Web-Lab-Security-Posture-Auditor/1.0"
TIMEOUT_SECONDS = 10


def _compute_fingerprint(tool: str, rule: str, target: str) -> str:
    """Generate deterministic SHA-256 fingerprint for finding deduplication."""
    seed = f"{tool}:{rule}:{target}"
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()


def inspect_url(target_url: str) -> dict[str, Any]:
    """Inspect live URL and return raw findings, metrics, and security grade.

    Args:
        target_url: Web application URL (e.g. https://example.com or http://127.0.0.1:5000)

    Returns:
        dict containing:
            - target_url: str
            - status_code: int
            - response_time_ms: float
            - findings: list[dict]
            - grade_result: dict
            - server_headers: dict
    """
    url = target_url.strip()
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    parsed = urlparse(url)
    is_https = parsed.scheme == "https"
    is_localhost = parsed.hostname in ("localhost", "127.0.0.1", "::1")

    findings: list[dict[str, Any]] = []
    headers: dict[str, str] = {}
    status_code = 0
    elapsed_ms = 0.0

    try:
        session = requests.Session()
        session.headers.update({"User-Agent": DEFAULT_USER_AGENT})
        response = session.get(url, timeout=TIMEOUT_SECONDS, allow_redirects=True, verify=False)
        status_code = response.status_code
        elapsed_ms = round(response.elapsed.total_seconds() * 1000, 2)
        headers = dict(response.headers)
    except RequestException as exc:
        logger.warning(f"Failed to connect to target URL '{url}': {exc}")
        # Return connection failure finding
        err_finding = {
            "title": "Endpoint Connection Failure",
            "description": f"Failed to complete HTTP handshake with {url}: {exc}",
            "category": "Transport & TLS",
            "cwe_id": "CWE-1188",
            "severity": "CRITICAL",
            "confidence": "HIGH",
            "target_component": url,
            "evidence_snippet": str(exc),
            "remediation_guidance": "Verify host availability, DNS resolution, and firewall reachability.",
            "fingerprint": _compute_fingerprint("URL_INSPECTOR", "CONN_FAIL", url),
        }
        grade_res = grade_posture([err_finding], mode="URL")
        return {
            "target_url": url,
            "status_code": 0,
            "response_time_ms": 0.0,
            "findings": [err_finding],
            "grade_result": grade_res,
            "server_headers": {},
        }

    # Normalize header keys to lowercase for inspection
    h_lower = {k.lower(): v for k, v in headers.items()}

    # 1. Transport & TLS
    if not is_https and not is_localhost:
        findings.append(
            {
                "title": "Insecure Plaintext Transport (HTTP)",
                "description": f"Target endpoint '{url}' transmits sensitive application traffic without TLS encryption.",
                "category": "Transport & TLS",
                "cwe_id": "CWE-319",
                "severity": "HIGH",
                "confidence": "HIGH",
                "target_component": url,
                "evidence_snippet": f"Scheme: {parsed.scheme}",
                "remediation_guidance": "Deploy valid TLS certificates and enforce strict HTTPS redirection across all endpoints.",
                "fingerprint": _compute_fingerprint("URL_INSPECTOR", "NO_HTTPS", url),
            }
        )

    # Strict-Transport-Security (HSTS)
    if is_https:
        hsts = h_lower.get("strict-transport-security")
        if not hsts:
            findings.append(
                {
                    "title": "Missing HTTP Strict Transport Security (HSTS)",
                    "description": "The 'Strict-Transport-Security' header is absent, leaving users vulnerable to SSL-stripping man-in-the-middle attacks.",
                    "category": "Transport & TLS",
                    "cwe_id": "CWE-523",
                    "severity": "MEDIUM",
                    "confidence": "HIGH",
                    "target_component": url,
                    "evidence_snippet": "Header 'Strict-Transport-Security' is missing from server response.",
                    "remediation_guidance": "Configure 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'.",
                    "fingerprint": _compute_fingerprint("URL_INSPECTOR", "MISSING_HSTS", url),
                }
            )
        elif "max-age" not in hsts:
            findings.append(
                {
                    "title": "Invalid HSTS Configuration",
                    "description": f"The HSTS header is present but does not declare a valid max-age directive: {hsts}",
                    "category": "Transport & TLS",
                    "cwe_id": "CWE-523",
                    "severity": "LOW",
                    "confidence": "HIGH",
                    "target_component": url,
                    "evidence_snippet": f"Strict-Transport-Security: {hsts}",
                    "remediation_guidance": "Specify a valid max-age directive (e.g. max-age=31536000).",
                    "fingerprint": _compute_fingerprint("URL_INSPECTOR", "INVALID_HSTS", url),
                }
            )

    # 2. Content Security Policy (CSP)
    csp = h_lower.get("content-security-policy")
    if not csp:
        findings.append(
            {
                "title": "Missing Content-Security-Policy (CSP)",
                "description": "Content-Security-Policy header is missing, eliminating browser-level defense-in-depth against Cross-Site Scripting (XSS) and data injection.",
                "category": "Security Headers",
                "cwe_id": "CWE-1021",
                "severity": "HIGH",
                "confidence": "HIGH",
                "target_component": url,
                "evidence_snippet": "Header 'Content-Security-Policy' is absent.",
                "remediation_guidance": "Define a robust Content-Security-Policy restricting script, style, and object execution.",
                "fingerprint": _compute_fingerprint("URL_INSPECTOR", "MISSING_CSP", url),
            }
        )
    else:
        if "'unsafe-inline'" in csp and "nonce-" not in csp:
            findings.append(
                {
                    "title": "Permissive Content-Security-Policy (unsafe-inline allowed)",
                    "description": "CSP allows 'unsafe-inline' script execution without nonces or hashes, weakening protection against stored or reflected XSS.",
                    "category": "Security Headers",
                    "cwe_id": "CWE-1021",
                    "severity": "LOW",
                    "confidence": "MEDIUM",
                    "target_component": url,
                    "evidence_snippet": f"Content-Security-Policy: {csp[:120]}...",
                    "remediation_guidance": "Replace 'unsafe-inline' with cryptographic script nonces or SHA-256 hashes.",
                    "fingerprint": _compute_fingerprint("URL_INSPECTOR", "CSP_UNSAFE_INLINE", url),
                }
            )

    # 3. X-Content-Type-Options
    xcto = h_lower.get("x-content-type-options")
    if not xcto or xcto.lower().strip() != "nosniff":
        findings.append(
            {
                "title": "Missing or Misconfigured X-Content-Type-Options",
                "description": "Header 'X-Content-Type-Options: nosniff' is not set. Browsers may perform MIME sniffing on untrusted user uploads.",
                "category": "Security Headers",
                "cwe_id": "CWE-79",
                "severity": "MEDIUM",
                "confidence": "HIGH",
                "target_component": url,
                "evidence_snippet": f"X-Content-Type-Options: {xcto or 'absent'}",
                "remediation_guidance": "Add 'X-Content-Type-Options: nosniff' to all outgoing HTTP responses.",
                "fingerprint": _compute_fingerprint("URL_INSPECTOR", "MISSING_XCTO", url),
            }
        )

    # 4. X-Frame-Options / Clickjacking
    xfo = h_lower.get("x-frame-options")
    has_frame_ancestors = csp and "frame-ancestors" in csp
    if not xfo and not has_frame_ancestors:
        findings.append(
            {
                "title": "Missing Clickjacking Defense (X-Frame-Options / frame-ancestors)",
                "description": "Neither 'X-Frame-Options' nor CSP 'frame-ancestors' is declared. The application may be framed within malicious iframes.",
                "category": "Security Headers",
                "cwe_id": "CWE-1021",
                "severity": "MEDIUM",
                "confidence": "HIGH",
                "target_component": url,
                "evidence_snippet": "No X-Frame-Options or frame-ancestors directive found.",
                "remediation_guidance": "Emit 'X-Frame-Options: DENY' (or 'SAMEORIGIN') or CSP 'frame-ancestors 'none''.",
                "fingerprint": _compute_fingerprint("URL_INSPECTOR", "MISSING_XFO", url),
            }
        )

    # 5. Referrer-Policy
    ref_pol = h_lower.get("referrer-policy")
    if not ref_pol:
        findings.append(
            {
                "title": "Missing Referrer-Policy Header",
                "description": "Referrer-Policy header is absent. Browsers may leak sensitive URL parameters or internal paths in the Referer header.",
                "category": "Security Headers",
                "cwe_id": "CWE-116",
                "severity": "LOW",
                "confidence": "HIGH",
                "target_component": url,
                "evidence_snippet": "Header 'Referrer-Policy' is absent.",
                "remediation_guidance": "Declare 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer'.",
                "fingerprint": _compute_fingerprint("URL_INSPECTOR", "MISSING_REF_POL", url),
            }
        )

    # 6. Permissions-Policy
    perm_pol = h_lower.get("permissions-policy")
    if not perm_pol:
        findings.append(
            {
                "title": "Missing Permissions-Policy Header",
                "description": "Permissions-Policy is not configured to restrict browser API access (camera, microphone, geolocation).",
                "category": "Security Headers",
                "cwe_id": "CWE-1021",
                "severity": "LOW",
                "confidence": "MEDIUM",
                "target_component": url,
                "evidence_snippet": "Header 'Permissions-Policy' is absent.",
                "remediation_guidance": "Add 'Permissions-Policy: camera=(), microphone=(), geolocation=()'.",
                "fingerprint": _compute_fingerprint("URL_INSPECTOR", "MISSING_PERM_POL", url),
            }
        )

    # 7. Server Banner / Technology Fingerprint Leakage
    server_hdr = h_lower.get("server")
    if server_hdr:
        # Check if version numbers or detailed technology is leaked (e.g. Apache/2.4.41, nginx/1.18.0)
        has_version = bool(re.search(r"/\d+(\.\d+)?", server_hdr))
        if has_version or any(
            t in server_hdr.lower() for t in ("werkzeug", "apache", "nginx", "iis", "kestrel")
        ):
            findings.append(
                {
                    "title": "Server Banner Information Disclosure",
                    "description": f"The 'Server' response header discloses precise server technology: '{server_hdr}', assisting attacker fingerprinting.",
                    "category": "Information Disclosure",
                    "cwe_id": "CWE-200",
                    "severity": "LOW",
                    "confidence": "HIGH",
                    "target_component": url,
                    "evidence_snippet": f"Server: {server_hdr}",
                    "remediation_guidance": "Strip or suppress granular version tokens from the 'Server' response header.",
                    "fingerprint": _compute_fingerprint("URL_INSPECTOR", "SERVER_BANNER", url),
                }
            )

    x_powered_by = h_lower.get("x-powered-by")
    if x_powered_by:
        findings.append(
            {
                "title": "Technology Stack Disclosure via X-Powered-By",
                "description": f"The 'X-Powered-By' header exposes internal backend framework details: '{x_powered_by}'.",
                "category": "Information Disclosure",
                "cwe_id": "CWE-200",
                "severity": "LOW",
                "confidence": "HIGH",
                "target_component": url,
                "evidence_snippet": f"X-Powered-By: {x_powered_by}",
                "remediation_guidance": "Disable or remove the 'X-Powered-By' header in framework server configuration.",
                "fingerprint": _compute_fingerprint("URL_INSPECTOR", "POWERED_BY", url),
            }
        )

    # 8. Cookie Security Analysis
    for cookie in response.cookies:
        c_name = cookie.name
        # Check HttpOnly
        if not cookie.has_nonstandard_attr("httponly") and not getattr(cookie, "_rest", {}).get(
            "HttpOnly"
        ):
            findings.append(
                {
                    "title": f"Cookie '{c_name}' Missing HttpOnly Flag",
                    "description": f"The cookie '{c_name}' does not have the HttpOnly flag enabled, making it accessible via client-side JavaScript (XSS theft).",
                    "category": "Cookie Protection",
                    "cwe_id": "CWE-1004",
                    "severity": "MEDIUM",
                    "confidence": "HIGH",
                    "target_component": f"Cookie: {c_name}",
                    "evidence_snippet": f"Set-Cookie attribute HttpOnly is absent for '{c_name}'.",
                    "remediation_guidance": f"Add the 'HttpOnly' flag when issuing the '{c_name}' cookie.",
                    "fingerprint": _compute_fingerprint(
                        "URL_INSPECTOR", f"COOKIE_NO_HTTPONLY_{c_name}", url
                    ),
                }
            )

        # Check Secure
        if not cookie.secure and (is_https or not is_localhost):
            findings.append(
                {
                    "title": f"Cookie '{c_name}' Missing Secure Flag",
                    "description": f"The cookie '{c_name}' is not marked Secure and can be leaked over plaintext HTTP transmissions.",
                    "category": "Cookie Protection",
                    "cwe_id": "CWE-614",
                    "severity": "MEDIUM",
                    "confidence": "HIGH",
                    "target_component": f"Cookie: {c_name}",
                    "evidence_snippet": f"Set-Cookie attribute Secure is absent for '{c_name}'.",
                    "remediation_guidance": f"Ensure 'Secure' flag is set for '{c_name}' in all production deployments.",
                    "fingerprint": _compute_fingerprint(
                        "URL_INSPECTOR", f"COOKIE_NO_SECURE_{c_name}", url
                    ),
                }
            )

    # 9. CORS Analysis
    cors_origin = h_lower.get("access-control-allow-origin")
    if cors_origin == "*":
        findings.append(
            {
                "title": "Permissive Wildcard Access-Control-Allow-Origin",
                "description": "Access-Control-Allow-Origin is set to wildcard '*', allowing any third-party web origin to read response content.",
                "category": "Security Headers",
                "cwe_id": "CWE-942",
                "severity": "LOW",
                "confidence": "HIGH",
                "target_component": url,
                "evidence_snippet": "Access-Control-Allow-Origin: *",
                "remediation_guidance": "Restrict Access-Control-Allow-Origin to trusted explicit origins.",
                "fingerprint": _compute_fingerprint("URL_INSPECTOR", "CORS_WILDCARD", url),
            }
        )

    # Categories tested
    categories = [
        "Transport & TLS",
        "Security Headers",
        "Cookie Protection",
        "Information Disclosure",
    ]

    grade_result = grade_posture(findings, categories_tested=categories, mode="URL")

    return {
        "target_url": url,
        "status_code": status_code,
        "response_time_ms": elapsed_ms,
        "findings": findings,
        "grade_result": grade_result,
        "server_headers": headers,
    }
