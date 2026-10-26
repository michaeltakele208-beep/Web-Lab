"""Broken Access Control / IDOR scenario adapter (VADL-AC-001)."""

from app.engine.adapters.base import BaseScenarioAdapter
from app.engine.evidence import build_evidence
from app.engine.semantics import ErrorCategory, ResultOutcome
from app.models.lab import LabRecord, LabTarget


class IDORAdapter(BaseScenarioAdapter):
    """Offensive adapter for Insecure Direct Object Reference (IDOR) access control testing."""

    scenario_id = "VADL-AC-001"

    def _run_test(
        self,
        target: LabTarget,
        edition: str,
        client,
        test_identifier: str,
        timeout_seconds: int,
        max_evidence_bytes: int,
    ) -> tuple[ResultOutcome, ErrorCategory | None, str]:
        # Target record: synthetic confidential record belonging to synthetic-user-2
        target_record_id = 2
        endpoint = f"/lab/{edition}/records/{target_record_id}"

        # Fetch record metadata directly for comparison
        from app.extensions import db

        target_record = db.session.get(LabRecord, target_record_id)
        expected_leak_marker = target_record.confidential_note if target_record else "RESTRICTED"

        if edition == "vulnerable":
            # Attempt unauthenticated / cross-tenant object access
            response = client.get(endpoint)
            status_code = response.status_code
            html = response.get_data(as_text=True)

            if status_code == 404 and "Vulnerable lab mode" in html:
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
                        response_body_snippet=html[:300],
                        expected_behavior="Vulnerable endpoint available",
                        observed_behavior="HTTP 404 (Vulnerable mode disabled)",
                        rationale="Target vulnerable lab mode is disabled in this environment.",
                        max_bytes=max_evidence_bytes,
                    ),
                )

            # Check if record 2 confidential data was retrieved without ownership check
            if status_code == 200 and expected_leak_marker in html:
                outcome = ResultOutcome.VULNERABILITY_CONFIRMED
                observed = (
                    f"Direct object reference allowed unauthorized retrieval of record #{target_record_id} "
                    f"belonging to '{target_record.owner_username if target_record else 'other_user'}'. HTTP 200 OK."
                )
                rationale = (
                    "Missing server-side ownership validation permits arbitrary horizontal object access "
                    "by simply incrementing numeric record identifiers."
                )
            else:
                outcome = ResultOutcome.VULNERABILITY_NOT_REPRODUCED
                observed = f"HTTP {status_code} returned without leaking target record."
                rationale = "Target record was not returned."

            evidence = build_evidence(
                scenario_id=self.scenario_id,
                test_identifier=test_identifier,
                target_edition=edition,
                request_method="GET",
                request_url=endpoint,
                response_status=status_code,
                response_body_snippet=html[:500],
                expected_behavior="Direct object reference exposes other user's confidential note without authorization",
                observed_behavior=observed,
                rationale=rationale,
                max_bytes=max_evidence_bytes,
            )
            return outcome, None, evidence

        else:  # edition == "secure"
            # 1. Anonymous attempt to access secure record
            anon_resp = client.get(endpoint)
            # Secure endpoint requires authentication and ownership validation
            is_anon_blocked = anon_resp.status_code in (302, 401, 403)

            # 2. Authenticated attempt as synthetic-user-1 (cross-user horizontal test)
            with client.session_transaction() as sess:
                # Mock session as an ordinary user who is NOT the owner of record #2
                sess["user_id"] = 99999
                sess["user_email"] = "unauthorized_viewer@vadl.local"
                sess["user_role"] = "user"

            auth_resp = client.get(endpoint)
            auth_html = auth_resp.get_data(as_text=True)
            is_cross_user_blocked = auth_resp.status_code == 403

            if is_anon_blocked and is_cross_user_blocked and expected_leak_marker not in auth_html:
                outcome = ResultOutcome.SECURITY_CHECK_PASSED
                observed = (
                    f"Anonymous request was rejected ({anon_resp.status_code}), and unauthorized cross-user "
                    f"request was strictly denied with HTTP 403 Forbidden. Ownership boundary enforced."
                )
                rationale = (
                    "Server-side authorization verified that record.owner_email matches the authenticated user identity "
                    "before granting access."
                )
            elif expected_leak_marker in auth_html:
                outcome = ResultOutcome.VULNERABILITY_CONFIRMED
                observed = f"Confidential note was returned to unauthorized user! HTTP {auth_resp.status_code}"
                rationale = "Broken access control: cross-user object access succeeded."
            else:
                outcome = ResultOutcome.VULNERABILITY_NOT_REPRODUCED
                observed = (
                    f"Anonymous: {anon_resp.status_code}, Cross-user: {auth_resp.status_code}"
                )
                rationale = "Object access was blocked, but not with standard 403 code."

            evidence = build_evidence(
                scenario_id=self.scenario_id,
                test_identifier=test_identifier,
                target_edition=edition,
                request_method="GET",
                request_url=endpoint,
                response_status=auth_resp.status_code,
                response_body_snippet=auth_html[:500],
                expected_behavior="Server-side ownership verification returns HTTP 403 Forbidden for non-owners",
                observed_behavior=observed,
                rationale=rationale,
                max_bytes=max_evidence_bytes,
            )
            return outcome, None, evidence
