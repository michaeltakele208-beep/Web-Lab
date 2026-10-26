# Web Lab Security Posture & Vulnerability Assessment Platform

[![Project: Web Lab](https://img.shields.io/badge/Project-Web%20Lab-0284c7.svg)](docs/project-overview.md)
[![Phase](https://img.shields.io/badge/Phase-8%20Final%20Capstone%20Audit-10b981.svg)](docs/architecture.md)
[![Python](https://img.shields.io/badge/Python-3.11%20%7C%203.12-blue)](https://www.python.org/)
[![Tests: Pytest](https://img.shields.io/badge/Tests-149%20Passed-success)](tests/)
[![Security: Bandit](https://img.shields.io/badge/Security-Bandit%20AST%20Clean-success)](https://bandit.readthedocs.io/)
[![Audit: pip-audit](https://img.shields.io/badge/Audit-pip--audit%20Zero%20Vulnerabilities-success)](https://pypi.org/project/pip-audit/)
[![Linter: Ruff](https://img.shields.io/badge/Linter-Ruff%20Compliant-brightgreen)](https://docs.astral.sh/ruff/)

A cybersecurity engineering platform developed for hands on vulnerability assessment, live website posture grading, secure coding education, automated static code analysis, and empirical defensive remediation verification.

---

## 1. Project Purpose & Engineering Scope

The platform was engineered as an end-to-end practical capstone project demonstrating real-world cybersecurity engineering principles:

1. **Passive Web Posture & Header Auditing**: Non-destructive evaluation of target web servers against modern RFC specifications (RFC 6797 HSTS, RFC 7034 X-Frame-Options, Content Security Policy Level 3, RFC 6265 Cookie security flags, server version leakage).
2. **Deterministic 0–100 Security Scoring**: Transparent deduction weights (Critical -20, High -15, Medium -8, Low -3, Info -1) mapping to letter grades (A+, A, B, C, D, F).
3. **Source Code Archive Security Inspection (SAST & SCA)**: Safe ZIP unpacking with Zip-Slip path traversal defense (`_is_safe_path`) and decompression bomb limits, followed by AST-based static analysis (Bandit) and dependency CVE audits (pip-audit).
4. **Dual-Edition Laboratory Architecture**: Side-by-side comparison of intentionally vulnerable toy implementations (`/lab/vulnerable/*`) and hardened defensive references (`/lab/secure/*`) covering OWASP Top 10 vulnerabilities (SQL Injection, Stored XSS, IDOR, and Insecure Headers).
5. **Offensive Security Test Harness**: Controlled test execution adapters verifying attack vectors strictly against authorized targets on isolated non-routable loopback boundaries.
6. **Empirical Remediation Verification Workflow**: Automated state-machine tracking where mitigations cannot be manually marked `VERIFIED` without passing reproducible regression suites, sealed with SHA-256 evidence integrity hashes.
7. **Multi-Format Technical Reporting**: Pure-Python ReportLab PDF compilation and machine-readable JSON security exports for executive briefing and compliance review.

-
## 2. Architecture & Security Controls

```
+-----------------------------------------------------------------------------------+
|                              Web Lab Security Core                                |
+-----------------------------------------------------------------------------------+
|                                                                                   |
|  [Presentation & Auth Layer]                                                      |
|   - Flask Application Factory (app/__init__.py)                                   |
|   - Session Fixation Renewal (login_user session regeneration)                    |
|   - Cryptographic Double-Submit CSRF Defense (secrets.token_hex(32) & HMAC)       |
|   - Sliding Window Rate Limiting (5 failed auth attempts / 60 seconds)            |
|   - Three-Tier RBAC: user -> security_analyst -> admin                            |
|                                                                                   |
|  [Security Scanner & Assessment Core]                                             |
|   +------------------------------------+---------------------------------------+  |
|   | URL Posture Inspector (Passive)    | Source Archive Inspector (SAST/SCA)  |  |
|   | - TLS Certificate & Cipher Check   | - Zip-Slip Path Traversal Defense    |  |
|   | - CSP, HSTS, X-Frame, Referrer     | - Decompression Bomb Guards (25MB)    |  |
|   | - Cookie Flags (Secure, HttpOnly)  | - AST Python Static Analysis (Bandit)|  |
|   | - Server Header Information Leaks  | - Dependency CVE Inspection (Audit)  |  |
|   +------------------------------------+---------------------------------------+  |
|   | Posture Grader Engine (grader.py)                                          |  |
|   | - Deterministic deduction formula: Score = 100 - SUM(Severity_Weights)     |  |
|   | - Category breakdown & letter grade assignment (A+ to F)                   |  |
|   +----------------------------------------------------------------------------+  |
|                                                                                   |
|  [Controlled Laboratory Engine]                                                   |
|   - Isolated Blueprints: /lab/vulnerable (disabled in prod) & /lab/secure         |
|   - Target Hostname Allowlist: 127.0.0.1, localhost, vadl-isolated-network        |
|   - Cloud metadata (169.254.169.254) and external arbitrary scanning blocked      |
|                                                                                   |
|  [Defensive Verification & Reporting Engine]                                      |
|   - Remediation State Machine (PENDING -> VERIFIED | FAILED)                      |
|   - SHA-256 Evidence Integrity Hashes (Anti-tamper audit logs)                    |
|   - Pure-Python ReportLab PDF Generator & Normalized JSON Export                  |
+-----------------------------------------------------------------------------------+
```

---

## 3. Setup & Local Execution

### Step 1: Initialize Virtual Environment
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### Step 2: Install Audited Dependencies
```powershell
python -m pip install --upgrade pip
pip install -r requirements-dev.txt
```

### Step 3: Configure Environment
```powershell
Copy-Item .env.example .env
```

### Step 4: Run Database Migrations
```powershell
$env:FLASK_APP = "run.py"
flask db upgrade
```

### Step 5: Start Local Development Server
```powershell
python run.py
```

Access the platform at `http://127.0.0.1:5000/`.

---

## 4. Verification & Quality Assurance Suite

All 149 automated tests execute offline against an isolated in-memory test database with zero external network dependencies:

```powershell
# 1. Complete Automated Test Suite (149 passed)
.venv\Scripts\pytest.exe -q

# 2. Test Coverage Analysis
.venv\Scripts\pytest.exe --cov=app --cov-report=term-missing

# 3. Static Code Linting & Formatting Check (Ruff)
.venv\Scripts\ruff.exe check app tests
.venv\Scripts\ruff.exe format --check app tests

# 4. Static Application Security Testing (Bandit AST Audit)
.venv\Scripts\bandit.exe -r app -ll

# 5. Dependency Vulnerability Audit (pip-audit)
.venv\Scripts\pip-audit.exe -r requirements.txt
```

---

## 5. Project Structure

```
Web Lab/
├── app/
│   ├── admin/               Administrator console & user role management
│   ├── assessments/         Assessment execution history & evidence logs
│   ├── auth/                Authentication, scrypt password hashing, session renewal
│   ├── cli.py               Out-of-band administrative CLI commands
│   ├── config.py            Environment configurations (Development, Testing, Production)
│   ├── dashboard/           Live telemetry, posture grading metrics, scan overview
│   ├── extensions.py        SQLAlchemy, Flask-Migrate, Flask-Login extensions
│   ├── lab/                 Dual-edition vulnerable & hardened educational scenarios
│   ├── models/              Normalized SQLAlchemy ORM models (Users, Scans, Findings)
│   ├── remediations/        Remediation state machine & regression verification
│   ├── reports/             ReportLab PDF compilation & JSON export generator
│   ├── scanner/             Multi-tool scanner orchestration, URL inspector, ZIP inspector
│   ├── security/            Cryptographic CSRF validation & sliding window rate limiter
│   ├── static/              CSS stylesheets, UI components, brand assets
│   └── templates/           Jinja2 templates (dashboard, scanners, base layout)
├── docs/                    Technical documentation, viva preparation, and evidence logs
├── migrations/              Alembic database schema migrations
├── tests/                   149 automated pytest test suites
├── requirements.txt         Production runtime dependencies
├── requirements-dev.txt     Development and auditing tools
├── pyproject.toml           Ruff and pytest tool configuration
└── run.py                   Application entry point



