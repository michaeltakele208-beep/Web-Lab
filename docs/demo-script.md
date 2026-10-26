# Web Lab Platform — Live Examination Demonstration Script (10–15 Minutes)

**Project**: Web Lab — Security Posture & Vulnerability Assessment Platform  
**Program**: Web Lab Academic Platform Cyber Summer Camp Capstone  
**Target Audience**: Academic Evaluators, University Examiners, and Cybersecurity Assessment Panel  
**Presenter Role**: Student Security Engineer / Lab Architect  
**Objective**: Demonstrate end-to-end capabilities across all platform modules within 10 to 15 minutes.

---

## Pre-Demonstration Setup (Execute Before Presentation)

Open PowerShell in the project directory:
```powershell
# 1. Activate Virtual Environment
.\.venv\Scripts\Activate.ps1

# 2. Upgrade Database Migrations
flask db upgrade

# 3. Seed Demonstration Targets & Scenarios
flask lab seed

# 4. Provision Initial Administrator and Security Analyst Accounts
flask user create-admin --email admin@vadl.local --name "Lab Administrator" --password "AdminSecurePass123!@"
flask user promote --email analyst@vadl.local --role security_analyst

# 5. Start Development Server
$env:FLASK_CONFIG = "development"
$env:VADL_ENABLE_VULNERABLE_LAB = "true"
python run.py
```
*Expected Server Output*: Running on `http://127.0.0.1:5000` (Press CTRL+C to quit).

---

## Demonstration Script & Step-by-Step Walkthrough

### Step 1: Project Objective & Architecture (Minutes 0:00 – 2:00)
- **Spoken Overview**:
  > "Distinguished examiners, today I am presenting the Web Lab — Security Posture & Vulnerability Assessment Platform, developed as a capstone engineering project for the Web Lab Cybersecurity Engineering Project. The platform addresses a critical challenge in cybersecurity education: students frequently learn how to execute exploits, but rarely learn how to implement robust defensive mitigations, perform live posture scoring against RFC specifications, conduct safe static code analysis, or empirically verify that a patch neutralized an attack vector. The platform pairs live URL and source code ZIP scanning engines with dual-edition educational labs, automated regression verification, and ReportLab PDF security reporting."
- **Action**: Open browser to `http://127.0.0.1:5000/`.
- **Expected Observation**:
  - The **Web Lab Security Operations Dashboard** loads cleanly with real database telemetry.
  - Overall Posture Grade dial displays the current platform grade (e.g. `A+ (100/100)`).
  - Unauthenticated Guest Session notice confirms public read-only mode.

---

### Step 2: Seamless In-Page Authentication & Role-Based Authorization (Minutes 2:00 – 3:30)
- **Spoken Highlight**:
  > "To streamline evaluation and avoid interrupting the review workflow, the platform implements seamless in-page authentication without forcing the user to navigate to an isolated login screen."
- **Action 1**: Click the **`[Analyst Access]`** button directly in the top navigation bar or the Operational Session banner.
- **Expected Observation**:
  - Instant elevation: session updates immediately to **`Senior Security Analyst`** (`analyst@vadl.local`).
  - Operational Session banner displays the `SECURITY_ANALYST` role badge.
  - Navigation unlocks: `New Scan`, `Findings`, `Remediations`, `Audit Reports`, and `Compare`.
- **Action 2 (Negative Authorization Test)**: Attempt to navigate to `http://127.0.0.1:5000/admin/users`.
- **Expected Observation**:
  - Access is denied with **HTTP 403 Forbidden**. Demonstrates strict server-side RBAC: analysts cannot modify user roles or administrative policies.
- **Action 3**: Click **`[Logout]`** in the header, then click **`Sign In`** to demonstrate the modal dialog. Show that examiners can use quick-fill chips or enter custom credentials on the spot.

---

### Step 3: Live Website Posture & Header Audit (Minutes 3:30 – 5:30)
- **Action 1**: On the dashboard, locate the **Quick Audit** search bar.
- **Action 2**: Click the preset button **`Local App (127.0.0.1:5000)`** and click **`Analyze Website →`**.
- **Expected Observation**:
  - Passive audit engine inspects the target endpoint in under 1 second.
  - Displays **Security Score & Grade** (e.g. Letter Grade A/B/C) with transparent deduction points:
    - Missing HSTS (`Strict-Transport-Security`): -15 pts
    - Missing Content Security Policy (`Content-Security-Policy`): -8 pts
    - Missing Frame Protection (`X-Frame-Options`): -3 pts
  - Displays response latency, HTTP status code, and full server response headers.

---

### Step 4: Source Code Archive (ZIP) Security Audit (Minutes 5:30 – 7:30)
- **Action 1**: Click **`Source Code ZIP Audit`** on the dashboard or navigate to `/scans`.
- **Action 2**: Select a Python web project ZIP archive (or test fixture archive).
- **Spoken Highlight**:
  > "Before unpacking, the audit engine enforces strict Zip-Slip defenses via `_is_safe_path` to prevent path traversal exploits (`../../etc/passwd`), while enforcing a 25MB archive limit to neutralize decompression bombs. It then automatically runs Bandit AST analysis and pip-audit dependency CVE checks against the extracted sandbox."
- **Action 3**: Click **`Upload & Execute Security Audit`**.
- **Expected Observation**:
  - Source code files analyzed counter displays.
  - Findings table lists identified security flaws mapped to CWE standards, line numbers, and severities.

---

### Step 5: Dual-Edition Vulnerable vs Hardened Lab (Minutes 7:30 – 9:30)
- **Scenario: SQL Injection (`SQLI-AUTH-01`)**:
  - Navigate to `http://127.0.0.1:5000/lab/vulnerable/sqli`.
  - Enter `' OR '1'='1` &rarr; Demonstrates unparameterized query bypass, dumping secret lab flags.
  - Navigate to `http://127.0.0.1:5000/lab/secure/sqli`.
  - Enter `' OR '1'='1` &rarr; Demonstrates parameterized query binding: query returns 0 rows safely without syntax manipulation.

---

### Step 6: Empirical Remediation & Verification Workflow (Minutes 9:30 – 11:30)
- **Action 1**: Navigate to `http://127.0.0.1:5000/remediations`.
- **Spoken Highlight**:
  > "In this platform, a security finding cannot be marked 'Resolved' by simply clicking a checkbox. The remediation state machine requires an automated regression test run against the secure target edition."
- **Action 2**: Open an active remediation ticket and trigger **`Run Verification Check`**.
- **Expected Observation**:
  - The verification harness executes the original exploit vector against the secure implementation.
  - State machine advances to **`VERIFIED`**.
  - Forensic response payload is sealed with an immutable **SHA-256 evidence integrity hash** in the audit log.

---

### Step 7: Technical & Executive PDF Security Reporting (Minutes 11:30 – 13:00)
- **Action 1**: Navigate to `http://127.0.0.1:5000/reports`.
- **Action 2**: Generate and download an Executive PDF Report.
- **Expected Observation**:
  - Downloads a pure-Python multi-page PDF compiled with ReportLab (`Page 1 of N`), including corporate header, methodology, executive grade dial, finding tables, and sanitized evidence snippets.
- **Action 3**: Navigate to `http://127.0.0.1:5000/reports/compare` to show the Scan Differential Comparator highlighting newly detected, resolved, and persistent vulnerabilities across scans.

---

### Step 8: Quality Assurance & Test Suite Summary (Minutes 13:00 – 14:00)
- **Action**: Switch to the terminal window and show the test verification suite:
  ```powershell
  .venv\Scripts\pytest.exe -q
  ```
- **Spoken Highlight**:
  > "The entire codebase is verified by 149 automated unit and integration tests passing with 100% success rate, 0 Bandit AST vulnerabilities, 0 pip-audit dependency CVEs, and 100% Ruff PEP-8 style compliance."
- **Closing**: Invite questions from the examination panel.
