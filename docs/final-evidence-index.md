# VADL Final Evidence Index & Demonstration Artifacts

This index catalogs the empirical verification evidence, security tool outputs, generated assessment reports, and verification digests produced during the Phase 8 project handover.

---

## 1. Directory Structure of Evidence

All artifacts are persisted in the [`docs/evidence/`](file:///c:/Users/HP/Downloads/Web%20Lab/docs/evidence/) directory:

```
docs/evidence/
├── vadl-security-assessment-report.pdf       # Compiled multi-page PDF security assessment report (8,444 bytes)
├── vadl-security-assessment-report.json      # Machine-readable JSON security report export
├── vadl-differential-comparison.json        # Scan-to-scan differential trend analysis output
├── bandit-scan-output.json                  # Bandit SAST scan output across app/ source code
└── remediation-verification.json            # SHA-256 sealed remediation verification evidence
```

---

## 2. Artifact Details & Integrity Verification

### A. Professional Multi-Page PDF Security Report
- **File**: [`docs/evidence/vadl-security-assessment-report.pdf`](file:///c:/Users/HP/Downloads/Web%20Lab/docs/evidence/vadl-security-assessment-report.pdf)
- **Size**: 8,444 bytes
- **Header Magic**: `%PDF-1.4`
- **Compiler**: Pure-Python `ReportLab 5.1.0` with `NumberedCanvas` (`Page X of Y`).
- **Sections Included**:
  1. Executive Title & Target Scope Metadata
  2. Scope Identification & Authorization Certification
  3. Assessment Methodology & Tool Parameters
  4. Executive Findings Summary & Severity Distribution Table
  5. Detailed Vulnerability Findings with Sanitized Technical Evidence
  6. Defensive Remediation Guidance & Empirical Verification Workflow
  7. Academic Disclaimers, Sign-off & Negative Assertion Warnings

### B. Normalized Machine-Readable JSON Export
- **File**: [`docs/evidence/vadl-security-assessment-report.json`](file:///c:/Users/HP/Downloads/Web%20Lab/docs/evidence/vadl-security-assessment-report.json)
- **Format**: JSON conforming to the VADL Canonical Findings Schema.
- **Payload Contents**: Contains `report_metadata`, `assessment_scope`, `scan_execution`, `findings_summary`, and `detailed_findings` array including tool finding IDs, CWE identifiers, OWASP categories, normalized severities, and sanitized evidence snippets.

### C. Differential Scan-to-Scan Comparison
- **File**: [`docs/evidence/vadl-differential-comparison.json`](file:///c:/Users/HP/Downloads/Web%20Lab/docs/evidence/vadl-differential-comparison.json)
- **Comparison Bounds**: Baseline Scan #1 vs. Comparison Scan #2.
- **Computed Counts**:
  - `new`: 0
  - `resolved`: 1 (SQL Injection resolved)
  - `persistent`: 1 (XSS awaiting remediation)
  - `severity_changes`: 0
  - `is_conclusive`: `True`

### D. Empirical Remediation Verification Record
- **File**: [`docs/evidence/remediation-verification.json`](file:///c:/Users/HP/Downloads/Web%20Lab/docs/evidence/remediation-verification.json)
- **Vulnerability Scenario**: `SQLI-AUTH-01` (SQL Injection in Catalog Search).
- **Workflow Status**: `VERIFIED` (Automated attack regression passed against secure edition).
- **Sanitized Verification Evidence**:
  ```
  Tested payload: ' OR '1'='1 against /lab/secure/sqli. HTTP 200 returned. Parameterized query treated input as literal string. Zero unauthorized records exposed.
  ```
- **Cryptographic Evidence Digest (SHA-256)**:
  `14a6839d3a29eb005363ab54dd40fa505f34b79e1e896bce1ed4f52ebf523cda`

### E. Static Security Analysis (Bandit SAST)
- **File**: [`docs/evidence/bandit-scan-output.json`](file:///c:/Users/HP/Downloads/Web%20Lab/docs/evidence/bandit-scan-output.json)
- **Tool Version**: Bandit 1.8.3
- **Audited Lines of Code**: 7,410 lines
- **Metrics**: 0 Medium Severity issues, 0 High Severity issues.
- **Intentional Lab Flaws**: Handled via documented `# nosec` exemptions strictly in `app/routes/lab_vulnerable.py`.

---

## 3. Automated Test Verification Summary

- **Total Test Count**: 137 tests
- **Passing**: 137 (100%)
- **Failing**: 0 (0%)
- **Skipped**: 0 (0%)
- **Test Modules**:
  - `test_auth.py` (11 tests)
  - `test_authorization.py` (11 tests)
  - `test_dashboard.py` (5 tests)
  - `test_engine_adapters.py` (5 tests)
  - `test_engine_orchestrator.py` (9 tests)
  - `test_engine_routes.py` (8 tests)
  - `test_health.py` (5 tests)
  - `test_lab_isolation.py` (7 tests)
  - `test_lab_scenarios.py` (4 tests)
  - `test_registration.py` (6 tests)
  - `test_remediation_workflow.py` (12 tests)
  - `test_reports.py` (11 tests)
  - `test_scan_comparison.py` (6 tests)
  - `test_scanner_adapters.py` (15 tests)
  - `test_scanner_orchestration.py` (5 tests)
  - `test_scanner_routes.py` (8 tests)
  - `test_security_basics.py` (9 tests)

---

## 4. Operational Boundaries & Remaining Disclosures

1. **Docker / OWASP ZAP Execution**:
   - The OWASP ZAP adapter is fully implemented and unit-tested via fixtures.
   - On the current local Windows development environment, the Docker CLI binary is not present on PATH. As designed by the VADL adapter architecture, the engine surfaces a structured `ToolNotAvailableError` rather than crashing or fabricating scan results.
   - For environments with Docker installed, containerized ZAP baseline scans are orchestrated over the isolated bridge network defined in `docker-compose.yml`.
2. **Rate Limiting Persistence**:
   - The sliding-window login rate limiter is in-memory. In enterprise multi-worker WSGI deployments, an external shared key-value store (e.g. Redis) should be attached.
