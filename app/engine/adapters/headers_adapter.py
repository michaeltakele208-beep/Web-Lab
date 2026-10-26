"""Security Headers scenario adapter (VADL-HEADERS-001)."""

from app.engine.adapters.base import BaseScenarioAdapter
from app.engine.evidence import build_evidence
from app.engine.semantics import ErrorCategory, ResultOutcome
from app.models.lab import LabTarget

REQUIRED_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": ("DENY", "SAMEORIGIN"),
    "Referrer-Policy": ("strict-origin-when-cross-origin", "no-referrer", "same-origin"),
    "Content-Security-Policy": ("frame-ancestors", "default-src"),
}


class SecurityHeadersAdapter(BaseScenarioAdapter):
    """Offensive adapter for evaluating defensive HTTP response headers."""

    scenario_id = "VADL-HEADERS-001"

    def _run_test(
        self,
        target: LabTarget,
        edition: str,
        client,
        test_identifier: str,
        timeout_seconds: int,
        max_evidence_bytes: int,
    ) -> tuple[ResultOutcome, ErrorCategory | None, str]:
        endpoint = f"/lab/{edition}/headers"
        response = client.get(endpoint)
        status_code = response.status_code
        headers = dict(response.headers)

        if edition == "vulnerable":
            if status_code == 404:
                return (
                    ResultOutcome.ERROR,
                    ErrorCategory.TARGET_DISABLED,
                    build_evidence(
                        scenario_id=self.scenario_id,
                        test_identifier=test_identifier,
                        target_edition=edition,
                        request_method="GET",
                        request_url=endpoint,
                        response_status=status_code,
                        expected_behavior="Vulnerable endpoint available",
                        observed_behavior="HTTP 404 (Vulnerable lab disabled)",
                        rationale="Target vulnerable lab mode is disabled in this environment.",
                        max_bytes=max_evidence_bytes,
                    ),
                )

            # Detect missing defensive security headers
            missing_headers = []
            for header_name in REQUIRED_SECURITY_HEADERS:
                if header_name not in headers:
                    missing_headers.append(header_name)

            if len(missing_headers) >= 3:
                outcome = ResultOutcome.VULNERABILITY_CONFIRMED
                observed = (
                    f"HTTP response omits vital defensive security headers: {', '.join(missing_headers)}. "
                    "Browser is left vulnerable to clickjacking and MIME-type sniffing."
                )
                rationale = (
                    "Security misconfiguration: absent CSP, nosniff, and frame controls allow client-side "
                    "exploitation via framing or MIME confusion."
                )
            else:
                outcome = ResultOutcome.VULNERABILITY_NOT_REPRODUCED
                observed = f"Fewer missing headers than expected: {missing_headers}"
                rationale = "Some defensive headers were present in vulnerable response."

            evidence = build_evidence(
                scenario_id=self.scenario_id,
                test_identifier=test_identifier,
                target_edition=edition,
                request_method="GET",
                request_url=endpoint,
                response_status=status_code,
                response_headers={
                    k: v
                    for k, v in headers.items()
                    if k.lower().startswith(("x-", "content-", "referrer"))
                },
                expected_behavior="Omission of security response headers (CSP, nosniff, frame controls)",
                observed_behavior=observed,
                rationale=rationale,
                max_bytes=max_evidence_bytes,
            )
            return outcome, None, evidence

        else:  # edition == "secure"
            missing_or_invalid = []

            for header_name, expected in REQUIRED_SECURITY_HEADERS.items():
                val = headers.get(header_name)
                if not val:
                    missing_or_invalid.append(f"{header_name} (MISSING)")
                elif isinstance(expected, tuple):
                    if not any(exp in val for exp in expected):
                        missing_or_invalid.append(f"{header_name} (Invalid value: '{val}')")
                elif val != expected:
                    missing_or_invalid.append(f"{header_name} (Expected '{expected}', got '{val}')")

            if not missing_or_invalid:
                outcome = ResultOutcome.SECURITY_CHECK_PASSED
                observed = (
                    "All required defensive security headers are correctly configured and enforced: "
                    "Content-Security-Policy (with frame restrictions), X-Content-Type-Options: nosniff, "
                    "X-Frame-Options: DENY, and Referrer-Policy."
                )
                rationale = (
                    "Defensive baseline verified. Note: The presence of security headers represents an essential "
                    "defense-in-depth barrier, but does not alone guarantee complete immunity from underlying application vulnerabilities."
                )
            else:
                outcome = ResultOutcome.VULNERABILITY_CONFIRMED
                observed = (
                    f"Deficiencies detected in secure headers: {', '.join(missing_or_invalid)}"
                )
                rationale = (
                    "Secure edition failed to enforce all expected defensive HTTP response headers."
                )

            evidence = build_evidence(
                scenario_id=self.scenario_id,
                test_identifier=test_identifier,
                target_edition=edition,
                request_method="GET",
                request_url=endpoint,
                response_status=status_code,
                response_headers={
                    k: v
                    for k, v in headers.items()
                    if k.lower().startswith(("x-", "content-", "referrer"))
                },
                expected_behavior="All defensive security headers present with hardened configurations",
                observed_behavior=observed,
                rationale=rationale,
                max_bytes=max_evidence_bytes,
            )
            return outcome, None, evidence
