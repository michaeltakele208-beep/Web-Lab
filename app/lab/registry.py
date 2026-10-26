"""Structured Vulnerability Scenario Registry for VADL (Phase 3)."""

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class VulnerabilityScenario:
    """Documented vulnerability scenario specification."""

    scenario_id: str
    title: str
    category: str
    description: str
    affected_feature: str
    vulnerable_behavior: str
    secure_behavior: str
    severity: str
    severity_rationale: str
    reproduction_steps: tuple[str, ...]
    remediation: str
    owasp_reference: str
    automated_test_id: str
    status: str = "not_assessed"

    def to_dict(self) -> dict:
        return asdict(self)


SCENARIO_SQLI = VulnerabilityScenario(
    scenario_id="VADL-SQLI-001",
    title="SQL Injection in Toy Product Lookup",
    category="A03:2021-Injection",
    description=(
        "Demonstrates how concatenating raw user input directly into SQL strings allows "
        "crafted queries to bypass application filtering and retrieve unlisted toy catalog records."
    ),
    affected_feature="Toy Product Catalog Lookup",
    vulnerable_behavior=(
        "Crafted category input (e.g. \"' OR '1'='1\") alters query semantics and retrieves "
        "unlisted toy records and test flags outside the requested category."
    ),
    secure_behavior=(
        "Query utilizes SQLAlchemy parameterized binding (:category). User input is treated "
        "strictly as literal data; crafted input returns no matching records."
    ),
    severity="HIGH",
    severity_rationale=(
        "SQL injection can lead to unauthorized data exposure, bypass of access restrictions, "
        "and potential database manipulation in untrusted environments."
    ),
    reproduction_steps=(
        "1. Navigate to /lab/vulnerable/sqli.",
        "2. Submit query category parameter: ' OR '1'='1.",
        "3. Observe all catalog records including secret toy test flags returned.",
    ),
    remediation=(
        "Always use parameterized prepared statements or ORM abstractions. Never interpolate "
        "or concatenate user-supplied strings into SQL queries."
    ),
    owasp_reference="OWASP Top 10:2021 A03 - Injection",
    automated_test_id="tests/test_lab_scenarios.py::test_sqli_vulnerable_and_secure",
    status="not_assessed",
)

SCENARIO_XSS = VulnerabilityScenario(
    scenario_id="VADL-XSS-001",
    title="Cross-Site Scripting (XSS) in Toy Message Board",
    category="A03:2021-Injection",
    description=(
        "Demonstrates how rendering user-submitted feedback without context-aware HTML entity "
        "encoding permits execution of arbitrary client-side markup."
    ),
    affected_feature="Toy Comment & Feedback Board",
    vulnerable_behavior=(
        "Input containing HTML markup (e.g. '<b id=\"injected-demo\">PoC</b>') is rendered "
        "unescaped into the DOM using an explicit bypass filter."
    ),
    secure_behavior=(
        "Input is safely encoded by Jinja's auto-escaping engine. Markup is rendered as literal "
        "text strings ('&lt;b&gt;...') rather than active DOM elements."
    ),
    severity="MEDIUM",
    severity_rationale=(
        "Unsanitized client-side rendering can allow session hijacking, defacement, or credential "
        "harvesting when executed within an authenticated browser context."
    ),
    reproduction_steps=(
        "1. Navigate to /lab/vulnerable/xss.",
        "2. Submit comment: '<span id=\"xss-poc\">synthetic-proof</span>'.",
        "3. Observe unescaped HTML element rendered directly in the response document.",
    ),
    remediation=(
        "Ensure all dynamic user-controlled strings are contextually HTML-entity encoded before "
        "interpolation into template responses. Never mark untrusted inputs as safe."
    ),
    owasp_reference="OWASP Top 10:2021 A03 - Injection (Cross-Site Scripting)",
    automated_test_id="tests/test_lab_scenarios.py::test_xss_vulnerable_and_secure",
    status="not_assessed",
)

SCENARIO_IDOR = VulnerabilityScenario(
    scenario_id="VADL-AC-001",
    title="Broken Object Level Authorization (IDOR) on Synthetic Records",
    category="A01:2021-Broken Access Control",
    description=(
        "Demonstrates how missing server-side authorization checks on resource identifiers "
        "allow one synthetic participant to view another participant's private lab record."
    ),
    affected_feature="Synthetic Confidential Note Lookup",
    vulnerable_behavior=(
        "Requesting /lab/vulnerable/records/<id> returns confidential notes belonging to other "
        "synthetic users without checking ownership."
    ),
    secure_behavior=(
        "Server-side verification confirms the authenticated user owns the requested record "
        "before rendering. Returns HTTP 403 Forbidden on ownership mismatch."
    ),
    severity="HIGH",
    severity_rationale=(
        "Failure to enforce object-level authorization allows unauthorized horizontal data access "
        "across tenant or participant boundaries."
    ),
    reproduction_steps=(
        "1. Authenticate as synthetic user 'synthetic-user-1'.",
        "2. Request record #2 belonging to 'synthetic-user-2'.",
        "3. Observe unauthorized access to synthetic user 2's confidential note in vulnerable edition.",
    ),
    remediation=(
        "Validate record ownership on the server for every request before returning data or "
        "performing operations. Never trust client-supplied resource identifiers implicitly."
    ),
    owasp_reference="OWASP Top 10:2021 A01 - Broken Access Control",
    automated_test_id="tests/test_lab_scenarios.py::test_idor_vulnerable_and_secure",
    status="not_assessed",
)

SCENARIO_HEADERS = VulnerabilityScenario(
    scenario_id="VADL-HEADERS-001",
    title="Missing & Insufficient HTTP Security Headers",
    category="A05:2021-Security Misconfiguration",
    description=(
        "Demonstrates the defensive significance of browser security headers by comparing an "
        "insecure endpoint lacking CSP, nosniff, and frame controls against a hardened endpoint."
    ),
    affected_feature="HTTP Response Header Configuration",
    vulnerable_behavior=(
        "HTTP response omits Content-Security-Policy, X-Content-Type-Options, X-Frame-Options, "
        "and Referrer-Policy, leaving client browsers reliant on permissive defaults."
    ),
    secure_behavior=(
        "HTTP response strictly enforces 'Content-Security-Policy: default-src \\'self\\'', "
        "'X-Content-Type-Options: nosniff', 'X-Frame-Options: DENY', and 'Referrer-Policy: strict-origin-when-cross-origin'."
    ),
    severity="LOW",
    severity_rationale=(
        "Missing security headers provide defense-in-depth weaknesses that augment other flaws "
        "(such as clickjacking and MIME-type confusion), though headers alone do not remediate "
        "underlying application bugs."
    ),
    reproduction_steps=(
        "1. Issue GET request to /lab/vulnerable/headers.",
        "2. Inspect response headers and observe absence of CSP, X-Frame-Options, and X-Content-Type-Options.",
        "3. Compare with /lab/secure/headers where all defense headers are present.",
    ),
    remediation=(
        "Configure baseline security headers across all web server responses, including strict "
        "Content-Security-Policy, X-Content-Type-Options nosniff, and frame restrictions."
    ),
    owasp_reference="OWASP Top 10:2021 A05 - Security Misconfiguration",
    automated_test_id="tests/test_lab_scenarios.py::test_security_headers_vulnerable_and_secure",
    status="not_assessed",
)

REGISTRY: dict[str, VulnerabilityScenario] = {
    SCENARIO_SQLI.scenario_id: SCENARIO_SQLI,
    SCENARIO_XSS.scenario_id: SCENARIO_XSS,
    SCENARIO_IDOR.scenario_id: SCENARIO_IDOR,
    SCENARIO_HEADERS.scenario_id: SCENARIO_HEADERS,
}


def get_all_scenarios() -> list[VulnerabilityScenario]:
    """Retrieve all documented laboratory scenarios."""
    return list(REGISTRY.values())


def get_scenario(scenario_id: str) -> VulnerabilityScenario | None:
    """Retrieve a specific scenario by its stable identifier."""
    return REGISTRY.get(scenario_id)
