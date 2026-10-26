"""Cross-Site Scripting (XSS) scenario adapter (VADL-XSS-001)."""

import re

from app.engine.adapters.base import BaseScenarioAdapter
from app.engine.evidence import build_evidence
from app.engine.semantics import ErrorCategory, ResultOutcome
from app.models.lab import LabTarget


class XSSAdapter(BaseScenarioAdapter):
    """Offensive adapter for stored Cross-Site Scripting testing on feedback boards."""

    scenario_id = "VADL-XSS-001"

    def _run_test(
        self,
        target: LabTarget,
        edition: str,
        client,
        test_identifier: str,
        timeout_seconds: int,
        max_evidence_bytes: int,
    ) -> tuple[ResultOutcome, ErrorCategory | None, str]:
        # Harmless, non-destructive HTML markup payload with unique deterministic identifier
        proof_id = f"vadl-xss-proof-{test_identifier.split('_')[-1]}"
        raw_payload = f'<span id="{proof_id}" class="vadl-test-indicator">XSS_POC</span>'

        endpoint = f"/lab/{edition}/xss"

        if edition == "vulnerable":
            # 1. Fetch vulnerable page to obtain session & CSRF token
            get_init = client.get(endpoint)
            if get_init.status_code == 404:
                return (
                    ResultOutcome.ERROR,
                    ErrorCategory.TARGET_DISABLED,
                    build_evidence(
                        scenario_id=self.scenario_id,
                        test_identifier=test_identifier,
                        target_edition=edition,
                        request_method="GET",
                        request_url=endpoint,
                        response_status=404,
                        response_body_snippet="HTTP 404 Not Found (Vulnerable lab disabled)",
                        expected_behavior="Vulnerable endpoint available",
                        observed_behavior="HTTP 404 Not Found",
                        rationale="Target vulnerable lab mode is disabled in this environment.",
                        max_bytes=max_evidence_bytes,
                    ),
                )

            csrf_token = ""  # nosec B105
            with client.session_transaction() as sess:
                csrf_token = sess.get("_csrf_token", "")

            # 2. Post comment with CSRF token
            client.post(
                endpoint,
                data={
                    "author": "OffensiveEngine",
                    "content": raw_payload,
                    "csrf_token": csrf_token,
                },
                follow_redirects=True,
            )

            # 3. Inspect rendered HTML for raw unescaped markup
            get_resp = client.get(endpoint)
            html = get_resp.get_data(as_text=True)

            # Check if the unescaped tag is rendered directly in DOM
            unescaped_pattern = re.compile(
                rf'<span\s+id="{proof_id}"[^>]*>XSS_POC</span>', re.IGNORECASE
            )
            is_unescaped = bool(unescaped_pattern.search(html))

            if is_unescaped:
                outcome = ResultOutcome.VULNERABILITY_CONFIRMED
                observed = (
                    f"Raw HTML markup was rendered unescaped in response: <span id='{proof_id}'>. "
                    "Server bypassed Jinja2 contextual escaping via markupsafe.Markup()."
                )
                rationale = "Untrusted user input was rendered without entity encoding, enabling arbitrary client-side DOM injection."
            else:
                outcome = ResultOutcome.VULNERABILITY_NOT_REPRODUCED
                observed = "Injected markup was either encoded or rejected."
                rationale = "The expected unescaped rendering was not reproduced."

            evidence = build_evidence(
                scenario_id=self.scenario_id,
                test_identifier=test_identifier,
                target_edition=edition,
                request_method="POST / GET",
                request_url=endpoint,
                request_payload={"content": raw_payload},
                response_status=get_resp.status_code,
                response_body_snippet=html[:500],
                expected_behavior="Unescaped HTML elements rendered directly in DOM tree",
                observed_behavior=observed,
                rationale=rationale,
                max_bytes=max_evidence_bytes,
            )
            return outcome, None, evidence

        else:  # edition == "secure"
            # 1. Fetch secure page to obtain session & CSRF token
            get_init = client.get(endpoint)
            if get_init.status_code != 200:
                return (
                    ResultOutcome.ERROR,
                    ErrorCategory.HTTP_ERROR,
                    build_evidence(
                        scenario_id=self.scenario_id,
                        test_identifier=test_identifier,
                        target_edition=edition,
                        request_method="GET",
                        request_url=endpoint,
                        response_status=get_init.status_code,
                        expected_behavior="HTTP 200",
                        observed_behavior=f"HTTP {get_init.status_code}",
                        rationale="Failed to load secure feedback endpoint.",
                        max_bytes=max_evidence_bytes,
                    ),
                )

            csrf_token = ""  # nosec B105
            with client.session_transaction() as sess:
                csrf_token = sess.get("_csrf_token", "")

            # 2. Submit payload with CSRF token
            client.post(
                endpoint,
                data={
                    "author": "OffensiveEngine",
                    "content": raw_payload,
                    "csrf_token": csrf_token,
                },
                follow_redirects=True,
            )

            # 3. Retrieve rendered comments and verify contextual entity encoding
            get_resp = client.get(endpoint)
            html = get_resp.get_data(as_text=True)

            raw_tag_present = raw_payload in html
            # Jinja auto-escaping encodes < as &lt; and > as &gt;
            escaped_indicator = (
                f"&lt;span id=&#34;{proof_id}&#34;" in html or f'&lt;span id="{proof_id}"' in html
            )

            if not raw_tag_present and escaped_indicator:
                outcome = ResultOutcome.SECURITY_CHECK_PASSED
                observed = (
                    "Untrusted markup was properly HTML-entity encoded into safe text representations "
                    "(&lt;span...&gt;). No unescaped executable elements entered the DOM."
                )
                rationale = (
                    "Contextual auto-escaping neutralizes Cross-Site Scripting by converting active control characters "
                    "into passive character entities."
                )
            elif raw_tag_present:
                outcome = ResultOutcome.VULNERABILITY_CONFIRMED
                observed = "Markup was rendered unescaped on secure endpoint!"
                rationale = "Defensive control failed to encode user input."
            else:
                outcome = ResultOutcome.VULNERABILITY_NOT_REPRODUCED
                observed = "Payload was not found in rendered document."
                rationale = "Input was filtered or excluded."

            evidence = build_evidence(
                scenario_id=self.scenario_id,
                test_identifier=test_identifier,
                target_edition=edition,
                request_method="POST / GET",
                request_url=endpoint,
                request_payload={"content": raw_payload},
                response_status=get_resp.status_code,
                response_body_snippet=html[:500],
                expected_behavior="Context-aware HTML entity encoding (&lt;span...&gt;) preventing DOM execution",
                observed_behavior=observed,
                rationale=rationale,
                max_bytes=max_evidence_bytes,
            )
            return outcome, None, evidence
