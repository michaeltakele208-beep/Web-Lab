"""SQL Injection scenario adapter (VADL-SQLI-001)."""

from urllib.parse import quote

from app.engine.adapters.base import BaseScenarioAdapter
from app.engine.evidence import build_evidence
from app.engine.semantics import ErrorCategory, ResultOutcome
from app.models.lab import LabTarget


class SQLInjectionAdapter(BaseScenarioAdapter):
    """Offensive adapter for SQL injection testing against product catalog search."""

    scenario_id = "VADL-SQLI-001"

    def _run_test(
        self,
        target: LabTarget,
        edition: str,
        client,
        test_identifier: str,
        timeout_seconds: int,
        max_evidence_bytes: int,
    ) -> tuple[ResultOutcome, ErrorCategory | None, str]:
        # Deterministic, non-destructive boolean tautology payload
        payload = "hardware' OR '1'='1"
        encoded_payload = quote(payload)

        endpoint = f"/lab/{edition}/sqli"
        query_url = f"{endpoint}?category={encoded_payload}"

        response = client.get(query_url)
        status_code = response.status_code
        html = response.get_data(as_text=True)

        secret_flag_indicator = "CONFIDENTIAL_LAB_FLAG"  # nosec B105
        executed_query_indicator = "Executed Query"

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
                        request_url=query_url,
                        request_payload=payload,
                        response_status=status_code,
                        response_body_snippet=html[:300],
                        expected_behavior="Vulnerable endpoint available",
                        observed_behavior="HTTP 404 Not Found (Vulnerable lab mode is disabled).",
                        rationale="Target vulnerable lab mode is disabled in this environment.",
                        max_bytes=max_evidence_bytes,
                    ),
                )

            # Vulnerability confirmation: Secret flag leaked or all products returned
            if secret_flag_indicator in html or executed_query_indicator in html:
                outcome = ResultOutcome.VULNERABILITY_CONFIRMED
                rationale = (
                    "Controlled SQL injection tautology altered the query abstract syntax tree, "
                    "bypassing category filtering and exposing unlisted test flags."
                )
            else:
                outcome = ResultOutcome.VULNERABILITY_NOT_REPRODUCED
                rationale = "The injected tautology did not alter query output as documented."

            # Extract snippet centered on secret flag if present
            flag_idx = html.find(secret_flag_indicator)
            if flag_idx != -1:
                start_i = max(0, flag_idx - 100)
                snippet = html[start_i : start_i + 400]
            else:
                snippet = html[:400]

            evidence = build_evidence(
                scenario_id=self.scenario_id,
                test_identifier=test_identifier,
                target_edition=edition,
                request_method="GET",
                request_url=query_url,
                request_payload=payload,
                response_status=status_code,
                response_body_snippet=snippet,
                expected_behavior="Semantic query alteration exposing secret test flags",
                observed_behavior="Query structure modified; test flag leaked into output"
                if outcome == ResultOutcome.VULNERABILITY_CONFIRMED
                else "Unchanged query output",
                rationale=rationale,
                max_bytes=max_evidence_bytes,
            )
            return outcome, None, evidence

        else:  # edition == "secure"
            if status_code != 200:
                return (
                    ResultOutcome.ERROR,
                    ErrorCategory.HTTP_ERROR,
                    build_evidence(
                        scenario_id=self.scenario_id,
                        test_identifier=test_identifier,
                        target_edition=edition,
                        request_method="GET",
                        request_url=query_url,
                        request_payload=payload,
                        response_status=status_code,
                        response_body_snippet=html[:300],
                        expected_behavior="HTTP 200 with secure parameter binding",
                        observed_behavior=f"HTTP {status_code} returned",
                        rationale="Unexpected response status from secure endpoint.",
                        max_bytes=max_evidence_bytes,
                    ),
                )

            # Defensive verification: Parameter binding prevents query alteration
            if secret_flag_indicator not in html:
                outcome = ResultOutcome.SECURITY_CHECK_PASSED
                rationale = (
                    "User input was strictly bound as literal data parameter (:category). "
                    "The SQL query structure was not altered, and restricted flags remained protected."
                )
            else:
                outcome = ResultOutcome.VULNERABILITY_CONFIRMED
                rationale = "Unexpected leakage of secret test flags on secure endpoint."

            evidence = build_evidence(
                scenario_id=self.scenario_id,
                test_identifier=test_identifier,
                target_edition=edition,
                request_method="GET",
                request_url=query_url,
                request_payload=payload,
                response_status=status_code,
                response_body_snippet=html[:500],
                expected_behavior="Input treated strictly as literal data without semantic query alteration",
                observed_behavior="0 matches for literal tautology string; secret flags protected"
                if outcome == ResultOutcome.SECURITY_CHECK_PASSED
                else "Flags leaked in secure edition",
                rationale=rationale,
                max_bytes=max_evidence_bytes,
            )
            return outcome, None, evidence
