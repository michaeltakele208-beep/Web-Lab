# Final Demonstration Walkthrough: Vulnerability Assessment and Defense Lab (VADL)

This document provides a step-by-step verification guide demonstrating the end-to-end capabilities of VADL across all seven completed development phases.

---

## 1. Environment Setup & Initialization

### Prerequisites
- Python 3.11+ or 3.12+ virtual environment
- SQLite 3 (or configured PostgreSQL target)
- Dependencies installed via `requirements.txt`

### Starting the Lab
```bash
# 1. Activate Virtual Environment
.venv\Scripts\activate   # Windows
# source .venv/bin/activate # Linux / macOS

# 2. Run Database Migrations to Head (Phase 7 Schema)
flask db upgrade

# 3. Seed Local Targets, Admin, and Analyst Users (Optional / Initial Setup)
flask create-admin admin@vadl.local AdminPassword123!@ "System Administrator"
flask promote-analyst analyst@vadl.local

# 4. Start Flask Application
flask run --host=127.0.0.1 --port=5000
```
Application will be accessible at: `http://127.0.0.1:5000`

---

## 2. Authentication & Role-Based Access Control

1. **Anonymous Exploration**:
   - Navigate to `http://127.0.0.1:5000/`.
   - Guest users observe high-level platform telemetry (Phase 7 Overview metrics) with administrative and scanner controls locked.
2. **Analyst Login**:
   - Navigate to `/login`.
   - Submit credentials for `analyst@vadl.local`.
   - Session identifier renewal is executed upon login with HTTP-only, SameSite cookies.
   - Quick launch action buttons appear on the dashboard (`Execute Scanner`, `Offensive Assessment`, `Remediations`, `Download Reports`).

---

## 3. Running Automated Security Scanners (Phase 6)

1. **Static Analysis (Bandit)**:
   - Navigate to `/scans` -> `Launch New Scan`.
   - Target: `Local Codebase` (Target #1).
   - Scanner: `Bandit (SAST)`. Profile: `Baseline`.
   - Click **Run Scan**.
   - Output is parsed and normalized into `NormalizedFinding` database records with CWE-89, CWE-79 mappings.
2. **Dependency Auditing (pip-audit)**:
   - Scanner: `pip-audit (SCA)`. Profile: `Requirements Check`.
   - Evaluates pinned dependencies against known PyPI CVE advisory databases.
3. **Dynamic Application Testing (OWASP ZAP)**:
   - Scanner: `OWASP ZAP (DAST)`.
   - Targets local non-routable loopback `http://127.0.0.1:5000` with automated baseline spider and passive scan rules.

---

## 4. Controlled Offensive Scenario Assessments (Phase 4)

1. **Initiate Scenario Test**:
   - Navigate to `/assessments` -> `New Assessment`.
   - Select Target: `VADL Local Lab Target` (`VULNERABLE` edition).
   - Select Scenarios:
     - `SQLI-AUTH-01`: SQL Injection in Authentication
     - `XSS-STORED-01`: Stored Cross-Site Scripting in Guestbook
     - `BAC-IDOR-01`: Broken Object-Level Authorization
     - `HDR-SEC-01`: Missing HTTP Security Headers
   - Click **Launch Assessment**.
2. **Review Assessment Execution**:
   - The engine validates target authorization, executes scenario test adapters, sanitizes collected payloads to `MAX_EVIDENCE_BYTES = 2048`, and confirms exploitability.
   - Assessment completes with status `COMPLETED` and outcome `VULNERABILITY_CONFIRMED`.

---

## 5. Defensive Remediation & Verification Workflow (Phase 5)

1. **Initiate Remediation Track**:
   - Navigate to `/remediations`.
   - Click **Create Remediation Track** for `SQLI-AUTH-01`.
   - Note baseline finding reference and attack payload details.
2. **Switch Target to Hardened Edition**:
   - Point the remediation engine to the `SECURE` target edition (`/lab/secure/...`).
3. **Trigger Automated Verification**:
   - Click **Verify Mitigation**.
   - The verification engine re-executes the exact attack payload against the secure edition.
   - The parameterized query neutralizes the injection vector while preserving valid user queries.
   - Verification status transitions to `VERIFIED` with SHA-256 evidence integrity hashing.

---

## 6. Security Operations Dashboard Telemetry (Phase 7)

1. **Navigate to Dashboard (`/` or `/dashboard`)**:
   - **Section A (Telemetry Cards)**:
     - Total Scans, Completed Scans, Total Findings, Open Findings, Confirmed Vulnerabilities, Verified Remediations.
     - Severity Distribution bar: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFORMATIONAL`.
   - **Section B (Unified History)**:
     - Chronological timeline combining tool scans and scenario assessments.
   - **Section C (Normalized Findings)**:
     - Interactive filtering by scanner type (`Bandit`, `pip-audit`, `ZAP`) and finding status.
   - **Section D (Remediation Status Taxonomy)**:
     - Breakdown of `Pending`, `Verified`, `Failed`, and `Inconclusive` remediation workflows.
2. **Data Integrity Guarantee**:
   - Telemetry reflects live database aggregate calculations. No hardcoded mock values.

---

## 7. Report Generation & Differential Trend Comparison (Phase 7)

1. **Download PDF Security Report**:
   - Navigate to `/reports` or any scan detail page (`/scans/<id>`).
   - Click **Download PDF Report**.
   - Generates a styled, multi-page vector PDF containing:
     - Executive Title & Scope block
     - Executive Summary & Severity breakdown table
     - Detailed Findings with sanitized evidence
     - Remediation guidance & verification status
     - Academic disclaimers and sign-off
2. **Export JSON Machine-Readable Report**:
   - Click **Export JSON Report**.
   - Validates JSON output against the unified findings schema.
3. **Execute Scan-to-Scan Comparison**:
   - Navigate to `/reports/compare`.
   - Baseline Run: Scan #1 (Vulnerable Baseline).
   - Comparison Run: Scan #2 (Post-Remediation Verification).
   - Click **Run Differential Comparison**.
   - Review categorized differential findings:
     - **Resolved Findings**: Flaws detected in baseline but mitigated in comparison.
     - **Persistent Findings**: Unmitigated vulnerabilities remaining across runs.
     - **New Findings**: Newly introduced security issues.
     - **Conclusiveness Flag**: Analytical disclosure whether comparison is mathematically sound.

---

## 8. Audit Trail Verification

1. Inspect `scan_audit_events` via CLI or Admin Console:
   - `REPORT_GENERATED`: Logged when PDF or JSON reports are created.
   - `REPORT_DOWNLOADED`: Logged each time an analyst downloads report artifacts.
   - `SCAN_COMPARISON`: Logged when differential trend analyses are executed.
   - Every entry records the actor ID, client IP, UTC timestamp, and SHA-256 artifact hashes.

---

## 9. Verification Summary Table

| Phase | Core Capability | Verification Mechanism | Status |
|---|---|---|---|
| **Phase 1** | Foundation & Lab Infrastructure | Health/Readiness checks, Docker compose, SQLite DB | ✅ Verified |
| **Phase 2** | Web Application & Identity | Role RBAC, session renewal, CSRF protection | ✅ Verified |
| **Phase 3** | Controlled Vulnerability Scenarios | Isolated Vulnerable & Secure scenario blueprints | ✅ Verified |
| **Phase 4** | Offensive Testing Engine | Adapter execution, evidence truncation, authorization | ✅ Verified |
| **Phase 5** | Defensive Controls & Remediation | Automated regression verification, evidence hashing | ✅ Verified |
| **Phase 6** | Automated Scanners (SAST/DAST/SCA) | Normalized findings schema, Bandit/pip-audit/ZAP | ✅ Verified |
| **Phase 7** | Security Dashboard & Reports | Live telemetry, PDF/JSON generation, scan diffing | ✅ Verified |
