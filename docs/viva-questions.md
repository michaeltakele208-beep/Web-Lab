# VADL Viva / Oral Examination Preparation Guide

This guide compiles 22 likely examiner questions with concise, technically accurate answers reflecting the actual implementation of the **Vulnerability Assessment and Defense Lab (VADL)**.

---

### Q1: What is a vulnerability assessment?
**Answer**: A vulnerability assessment is a systematic evaluation of an information system to discover, classify, and prioritize technical security weaknesses (such as missing patches, configuration flaws, or input validation bugs) without necessarily attempting to exploit them to their fullest impact.

### Q2: How does a vulnerability assessment differ from penetration testing?
**Answer**: A vulnerability assessment focuses on broad coverage—identifying as many potential security gaps as possible across an attack surface using automated tools and systematic audits. Penetration testing is goal-oriented and depth-focused—an authorized simulation where a tester chains specific vulnerabilities together to achieve an operational objective (such as gaining unauthorized access to a database or domain controller).

### Q3: What is SQL Injection (SQLi), and how does parameterized SQL prevent it?
**Answer**: SQL injection occurs when untrusted user input is directly concatenated or formatted into a database query string, allowing an attacker to manipulate query structure and syntax. Parameterized queries prevent SQL injection by separating the query structure (SQL code) from the data values. The database driver compiles the SQL statement first, and treats user inputs strictly as literal parameters, making it mathematically impossible for input strings to alter query semantics.

### Q4: What is Cross-Site Scripting (XSS), and how does contextual output encoding prevent it?
**Answer**: Cross-Site Scripting occurs when an application includes untrusted data in an HTTP response sent to a browser without proper validation or encoding, allowing attackers to execute malicious scripts in the victim's browser session. Contextual output encoding converts dangerous characters (such as `<`, `>`, `"`, `'`, `&`) into safe HTML character entity references (e.g., `&lt;`, `&gt;`). When the browser renders the page, it displays the characters visually as text rather than parsing them as executable HTML tags or script blocks.

### Q5: What is Broken Access Control / Insecure Direct Object References (IDOR)?
**Answer**: Broken Access Control occurs when an application fails to properly enforce server-side authorization policies, allowing users to access resources or perform actions outside their intended permissions. An Insecure Direct Object Reference (IDOR) happens when an application exposes a direct identifier to an internal object (e.g., `/lab/records/2`) and retrieves the record without verifying that the requesting session user actually owns or is authorized to view that object.

### Q6: What is OWASP ZAP, and what role does it serve in VADL?
**Answer**: OWASP ZAP (Zed Attack Proxy) is an open-source Dynamic Application Security Testing (DAST) tool. In VADL, ZAP operates as an automated containerized scanner that spiders the application at runtime over HTTP, analyzing live responses to detect passive vulnerabilities such as missing security headers, insecure cookie flags, and exposed metadata.

### Q7: What do Bandit and pip-audit detect, and how do they differ?
**Answer**: 
- **Bandit** is a Static Application Security Testing (SAST) tool for Python that parses the Abstract Syntax Tree (AST) of application source code to detect dangerous coding patterns (e.g., SQL string formatting, shell injections, unsafe YAML loaders).
- **pip-audit** is a Software Composition Analysis (SCA) tool that audits declared third-party dependencies in `requirements.txt` against known CVE vulnerability advisory databases (OSV and GitHub Advisory Database).

### Q8: What is the difference between a confirmed vulnerability and a false positive?
**Answer**: A confirmed vulnerability is an empirical security weakness verified through a reproducible test case or active exploit payload. A false positive occurs when an automated scanner flags a piece of code or an HTTP response as dangerous based on a heuristic signature, but the finding cannot actually be exploited in practice due to surrounding contextual controls or design intent.

### Q9: How does VADL verify that a vulnerability has been remediated?
**Answer**: VADL strictly prohibits manual assertions of resolution (such as clicking "fixed"). Instead, the Phase 5 automated verification service re-executes the original attack payload against the secure reference edition of the target. To achieve `VERIFIED` status, the test must confirm both that the attack vector was neutralized and that legitimate application functionality remains intact. The response evidence is then cryptographically hashed using SHA-256 (`evidence_sha256`) and committed to an immutable audit trail.

### Q10: Why are findings and assessments stored in a database rather than raw log files?
**Answer**: Persisting findings in a relational database (`NormalizedFinding`, `SecurityScan`, `Assessment`) enables:
1. Normalization across heterogeneous scanners (DAST, SAST, SCA) into a common schema.
2. Deterministic deduplication across recurring scans using SHA-256 flaw fingerprints.
3. Live SQL telemetry computation for operational dashboards without hardcoded mock data.
4. Scan-to-scan differential trend reporting (new, resolved, persistent findings).
5. Relational linkage between findings, remediation tickets, and verification audit trails.

### Q11: How is access control and authorization enforced in VADL?
**Answer**: Server-side authorization is enforced on every request using custom decorators `@login_required` and `@role_required(...)` across a three-tier hierarchy (`user`, `security_analyst`, `admin`). Permissions are verified against the server-side database session, not client-supplied form inputs or modifiable URL parameters. Furthermore, administrative actions prevent self-demotion or self-disabling.

### Q12: How does VADL defend against CSRF (Cross-Site Request Forgery)?
**Answer**: Every state-changing form includes a session-bound cryptographic CSRF token (`secrets.token_hex(32)`). A global `before_request` hook validates incoming tokens using constant-time string comparison (`hmac.compare_digest`) to prevent timing attacks. Missing or mismatched tokens result in immediate HTTP 400 rejection.

### Q13: How does VADL prevent Session Fixation attacks?
**Answer**: In `app/security.py`, upon successful credential authentication, `login_user()` immediately invokes `session.clear()` before issuing the authenticated session identifier. This regenerates the session identifier and purges any pre-authentication session tokens that an attacker may have pre-seeded in the user's browser.

### Q14: How are passwords stored and validated in VADL?
**Answer**: Passwords are never stored or logged in plaintext. They are hashed using Werkzeug's implementation of the `scrypt` key derivation function, which provides strong resistance against GPU and ASIC brute-force attacks through configurable memory and CPU cost parameters.

### Q15: Why is pure-Python ReportLab used for PDF generation instead of headless Chrome or WeasyPrint?
**Answer**: Headless Chrome (via Puppeteer) or tools like wkhtmltopdf introduce significant external dependencies (Node.js, Chromium binaries) and expose dangerous attack surfaces, including Server-Side Request Forgery (SSRF) and local file inclusion during PDF rendering. Pure-Python `ReportLab` runs entirely within the Python interpreter with zero external processes, allowing safe vector PDF compilation with full programmatic control over layout and XML-escaped text.

### Q16: How does VADL prevent Directory Traversal during report downloads?
**Answer**: In `app/reports/service.py`, report downloads resolve the requested file's absolute path and verify via `os.path.commonpath` that the resolved path resides strictly within the canonical `reports/` storage directory. Any attempted traversal using `../` or absolute system paths triggers an immediate HTTP 404 rejection.

### Q17: What is the "Zero-Finding Fallacy" or negative assertion problem?
**Answer**: A scan reporting `0 Findings` does not prove that an application is secure. It proves only that the specific heuristic signatures, rules, or test payloads configured in that tool did not trigger an alert on the inspected endpoints. Business-logic flaws, architectural bypasses, and unmodeled zero-day vectors cannot be ruled out by automated tools alone.

### Q18: What is the purpose of the `ScanComparisonService`?
**Answer**: `ScanComparisonService` computes the mathematical differential between two scans of the same target. It classifies findings into `newly_detected`, `resolved`, `persistent`, and `severity_changes`. Crucially, if either scan failed, timed out, or had execution errors, the service sets `is_conclusive=False` to ensure analysts do not draw false conclusions from incomplete scan data.

### Q19: Why are intentionally vulnerable endpoints separated into their own blueprint?
**Answer**: The vulnerable endpoints reside in `lab_vulnerable_bp` (`/lab/vulnerable/*`) and operate strictly over toy synthetic data. They are gated by `ENABLE_VULNERABLE_LAB=true`. If an operator attempts to run the application with vulnerable endpoints enabled in a production environment (`FLASK_CONFIG=production`), the application factory refuses to start with a fatal `ValueError`.

### Q20: What are HTTP security headers and why are they necessary?
**Answer**: HTTP security headers instruct the client browser to enable built-in defensive sandboxing mechanisms:
- `Content-Security-Policy`: Restricts the sources from which scripts, styles, and media can be loaded, mitigating XSS.
- `X-Content-Type-Options: nosniff`: Prevents MIME-confusion attacks where browsers execute non-script files as scripts.
- `X-Frame-Options: DENY`: Prevents the application from being embedded in an `<iframe>`, neutralizing clickjacking attacks.
- `Strict-Transport-Security`: Enforces HTTPS communication, preventing SSL-stripping man-in-the-middle attacks.

### Q21: What safety controls prevent students from using VADL as a general-purpose attack tool?
**Answer**: VADL incorporates strict target allowlisting (`validate_lab_target_url`). Targets must be pre-approved by an administrator in the database. The validation service explicitly rejects public IP addresses, external domain names, and cloud metadata endpoints (`169.254.169.254`). All network probes are restricted to non-routable loopback addresses and Docker container networks.

### Q22: What would you improve in a future version of the platform?
**Answer**: In a future phase, the platform could be enhanced with:
1. Distributed asynchronous task queues using Celery and Redis for long-running active ZAP scans.
2. Integration of CVSS v3.1 vector calculator widgets for custom risk scoring.
3. Automated pull-request CI/CD security gating with GitHub Actions integration.
4. Support for additional modern vulnerability scenarios, such as Server-Side Request Forgery (SSRF) and JWT token signature manipulation.

### Q23: How does the security posture grading engine calculate numerical scores and letter grades?
**Answer**: The grading engine (`app/scanner/grader.py`) uses a deterministic formula starting at a base score of 100 and deducting points strictly according to verified finding severity:
- **CRITICAL**: -20 points (e.g. unauthenticated remote code execution or raw SQL injection)
- **HIGH**: -15 points (e.g. missing CSRF protection or sensitive data exposure)
- **MEDIUM**: -8 points (e.g. missing Content Security Policy or insecure cookie flags)
- **LOW**: -3 points (e.g. missing X-Content-Type-Options or Referrer-Policy)
- **INFO**: -1 point (e.g. technology banner leakage)
The resulting score is clamped to `[0, 100]` and mapped to letter grades: A+ (≥95), A (≥90), B (≥80), C (≥70), D (≥60), and F (<60).

### Q24: How does the ZIP source code audit engine defend against Zip-Slip path traversal and decompression bombs?
**Answer**: When an archive is uploaded (`app/scanner/zip_inspector.py`):
1. **Zip-Slip Defense**: The `_is_safe_path` function checks each archive entry before extraction. It resolves both the destination directory and the proposed extraction target path using `.resolve()`. If the extracted file's resolved path does not strictly lie within the parent directory tree, extraction is aborted with a `ZipAuditError`.
2. **Decompression Bomb Protection**: The extractor enforces strict safety thresholds: maximum archive size of 25 MB (`MAX_ZIP_BYTES`), maximum extracted size of 60 MB (`MAX_UNCOMPRESSED_BYTES`), and maximum file count of 1,500 (`MAX_FILE_COUNT`). Any violation immediately halts extraction and purges the temporary sandbox.

### Q25: Why was frictionless in-page authentication and 1-click role elevation implemented instead of a separate login page?
**Answer**: In academic and professional demonstration contexts, forcing evaluators onto an isolated login screen creates unnecessary presentation friction and breaks the operational review flow. By embedding 1-click role elevation directly in the header and the dashboard's Operational Session banner (plus an interactive modal for custom inputs), examiners can instantly evaluate the platform under both `security_analyst` and `admin` privileges without leaving their current context. The underlying `/login` endpoint remains fully functional to ensure that automated headless tests continue to pass.

### Q26: How does the platform ensure that automated testing coverage is exhaustive across functional and security boundaries?
**Answer**: The platform is backed by 149 automated tests spanning 19 distinct test modules with 100% pass rate. The suite validates:
1. Negative security tests (rejecting weak passwords, brute-force rate-limiting at 5 attempts, rejecting invalid CSRF tokens).
2. Authorization boundaries (ensuring regular users cannot access analyst or admin routes).
3. SSRF and lab isolation (confirming non-whitelisted targets and metadata IPs are blocked).
4. SAST/SCA and scanner orchestrations (verifying parsing and deduplication across Bandit, pip-audit, and ZAP).
5. File and report safety (verifying directory traversal rejection on report downloads and safe PDF byte compilation).
