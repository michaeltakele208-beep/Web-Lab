# Defensive Remediation and Verification Workflow

## 1. Overview and Purpose

The **Defensive Remediation and Verification** subsystem (Phase 5) establishes a rigorous, defensible engineering lifecycle for addressing confirmed security weaknesses in the Vulnerability Assessment and Defense Lab (VADL).

A fundamental principle of VADL is that **remediations are never marked "fixed" on human assertion alone**. A vulnerability remediation status can only transition to `VERIFIED` when automated, reproducible regression test suites run against an authorized secure reference edition and verify that:
1. The offensive exploitation vector is neutralized or rejected.
2. Legitimate application functionality is preserved (regression check).
3. Database and data integrity are unaffected.
4. Cryptographic SHA-256 evidence integrity hashes are calculated and committed to the audit trail.

---

## 2. Remediation Workflow Lifecycle

Remediation records progress through a strict, auditable state machine:

```
 [OPEN]  <-----------------------------\
    |                                  |
    v                                  |
[IN_PROGRESS]                          |
    |                                  |
    v                                  |
[READY_FOR_VERIFICATION]               |
    |                                  |
    +-----> [Automated Verification]   |
                   |                   |
            +------+------+            |
            |             |            |
       (All Passed)  (Any Failed)      |
            |             |            |
            v             v            |
        [VERIFIED]    [REOPENED] ------/
```

### Workflow States (`RemediationStatus`)

| State | Description | Transition Rule |
| :--- | :--- | :--- |
| `OPEN` | Remediation record registered; awaiting triage or developer assignment. | Initial state or manual update from `REOPENED`. |
| `IN_PROGRESS` | Defensive architecture changes or patches are being implemented. | Manual update by Analyst or Admin. |
| `READY_FOR_VERIFICATION` | Code changes or defensive configurations are ready for regression testing. | Manual update by Analyst or Admin. |
| `VERIFIED` | All scenario-specific defensive tests and regression checks passed. | **Automated ONLY**. Manual transition is strictly rejected with `ValueError` (HTTP 400). |
| `REOPENED` | Automated verification failed, or an existing control was found broken. | Automated transition on verification failure, or manual reassignment. |

---

## 3. Verification Outcomes (`VerificationOutcome`)

| Outcome | Semantics |
| :--- | :--- |
| `VERIFIED` | Primary defense passed AND all functional regression checks succeeded against the secure edition. |
| `FAILED` | Primary defense failed (exploit still succeeded) OR a functional regression was detected. |
| `INCONCLUSIVE` | The execution completed, but definitive defensive differentiation could not be confirmed. |
| `ERROR` | Target unreachable, timeout occurred, or test harness encountered an unhandled execution fault. |
| `NOT_APPLICABLE` | The scenario does not have an automated verification adapter registered. |
| `UNVERIFIED` | Baseline state prior to running the verification service. |

---

## 4. Scenario-Specific Defensive Checks and Regressions

Each of the four lab vulnerability scenarios incorporates dual-phase verification:

### 1. SQL Injection (`VADL-SQLI-001`)
- **Primary Defense Verification**:
  - Executes tautology payload (`' OR '1'='1`) against `/lab/secure/sqli`.
  - Asserts that parameterized query bindings treat payload as a literal string filter, returning 0 products (and never returning secret lab flags).
- **Functional Regression Check**:
  - Dispatches legitimate search query (`?category=hardware`).
  - Verifies that valid products (`Firewall Appliance`, etc.) are returned with HTTP 200.
- **Data Integrity Check**:
  - Compares pre-test and post-test table row counts to ensure injection attempts caused no out-of-band alterations.

### 2. Cross-Site Scripting (`VADL-XSS-001`)
- **Primary Defense Verification**:
  - Submits active script payload (`<script>...`, `<span id="vadl-xss-proof-...`) to `/lab/secure/xss`.
  - Asserts that contextual Jinja auto-escaping renders character entities (`&lt;`, `&gt;`) rather than active HTML nodes.
- **Functional Regression Check**:
  - Submits valid plain text and punctuation (`"Defensive regression verification test comment."`).
  - Asserts that legitimate user text is rendered cleanly and accurately in the HTML output.

### 3. Broken Access Control / IDOR (`VADL-AC-001`)
- **Primary Defense Verification**:
  - Authenticates as an unauthorized user and requests private Record #2 belonging to another user.
  - Asserts that server-side object-level ownership check returns HTTP 403 Forbidden.
- **Functional Regression Check**:
  - Authenticates as the legitimate owner of Record #1 (`synthetic-user-1@vadl.local`).
  - Requests `/lab/secure/records/1` with ownership identity.
  - Asserts that legitimate owner is granted access with HTTP 200 and can view their confidential note.

### 4. HTTP Security Response Headers (`VADL-HEADERS-001`)
- **Primary Defense Verification**:
  - Requests `/lab/secure/headers`.
  - Asserts that hardened defensive headers are present:
    - `Content-Security-Policy` (with frame restrictions, script constraints)
    - `X-Content-Type-Options: nosniff`
    - `X-Frame-Options: DENY`
    - `Referrer-Policy: strict-origin-when-cross-origin`
- **Functional Regression Check**:
  - Asserts that response returns HTTP 200 and standard `Content-Type: text/html` is preserved without conflicting with security headers.

---

## 5. Comparative Differential Analysis

The `ComparisonService` links originating vulnerability test findings (`TestResult` with `target_edition="vulnerable"`) to defensive verification test results (`TestResult` with `target_edition="secure"`).

### Comparison Payload Structure
```json
{
  "remediation_id": 1,
  "scenario_id": "VADL-SQLI-001",
  "is_compatible": true,
  "delta_summary": "Vulnerability Successfully Remediated",
  "remediation_confirmed": true,
  "before": {
    "assessment_id": 12,
    "result_id": 45,
    "edition": "vulnerable",
    "outcome": "VULNERABILITY_CONFIRMED",
    "raw_evidence": "..."
  },
  "after": {
    "assessment_id": 15,
    "result_id": 62,
    "edition": "secure",
    "outcome": "SECURITY_CHECK_PASSED",
    "verification_status": "VERIFIED",
    "evidence_sha256": "3a7bd3e2360a3d29eea436cdfb27d37fee2d...c508",
    "raw_evidence": "..."
  }
}
```

### Evidence SHA-256 Integrity Digest
Whenever verification runs, the sanitized forensic evidence is hashed using SHA-256:
$$\text{Digest} = \text{SHA-256}(\text{Sanitized Evidence Text})$$
This digest is stored in `remediations.evidence_sha256` and recorded in `remediation_audit_events`.
> [!NOTE]
> The SHA-256 evidence digest provides tamper-detection and repeatable forensic reference for test evidence, ensuring that test artifacts cannot be silently altered after verification.

---

## 6. Access Control and Roles

- **Anonymous**: Access redirected to `/login` (HTTP 302).
- **Ordinary Users (`Role.USER`)**: Access rejected with HTTP 403 Forbidden.
- **Security Analysts (`Role.SECURITY_ANALYST`)**: Authorized to view, create, update statuses, execute verifications, and inspect diffs.
- **Administrators (`Role.ADMIN`)**: Full authorization across all remediation and verification features.
