# VADL Security & Isolation Model

## 1. Core Principles & Isolation Policy

The **Vulnerability Assessment and Defense Lab (VADL)** is designed exclusively for authorized cybersecurity education and defensive engineering research. Strict architectural isolation boundaries ensure that experimental components and future offensive testing routines cannot compromise the host environment or external networks.

> [!CAUTION]
> **Prohibition Against External Scanning**: Under no circumstances may VADL components be targeted against external websites, public domains, or networks without explicit written authorization. VADL's future scanning modules will enforce an internal target registry that rejects any target outside predefined lab subnets.

---

## 2. Authentication, Session & Access Control Threat Model (Phase 2)

Phase 2 introduces the identity layer. The following threat mitigations are active:

| Threat | Attack Vector | VADL Defensive Mitigation |
| :--- | :--- | :--- |
| **Credential Guessing / Brute Force** | Rapid automated password guessing on `/login` | In-memory sliding window rate limiter (max 5 attempts/min per IP) returning HTTP 429. |
| **User Enumeration** | Timing or error message discrepancy between valid and invalid usernames | Identical generic feedback ("Invalid email or password") returned with HTTP 401 for both unknown emails and bad passwords. |
| **Session Fixation** | Attacker presets session ID before victim authenticates | `login_user()` clears existing session state, regenerates the session identifier, and issues a fresh CSRF token upon successful authentication. |
| **Cross-Site Request Forgery (CSRF)** | Third-party origin triggers unauthorized POST actions | Cryptographic CSRF tokens (`secrets.token_hex(32)`) validated via `hmac.compare_digest` on all state-changing HTTP methods (`POST`, `PUT`, `DELETE`). |
| **Cookie Interception / Theft** | XSS or network eavesdropping captures session cookies | `SESSION_COOKIE_HTTPONLY = True`, `SESSION_COOKIE_SAMESITE = 'Lax'`, and `SESSION_COOKIE_SECURE = True` in production environments. |
| **Open Redirect** | Attacker crafts `?next=https://malicious.com` parameter | `is_safe_redirect()` parses candidate URLs with `urllib.parse.urlsplit` and rejects absolute URLs or protocol-relative paths (`//evil.com`). |
| **Privilege Escalation (Vertical)** | User alters role or tampers with administrative routes | Server-side `@role_required` decorator validates role against session identity on every request. Public registration always sets `role="user"`. |
| **Privilege Escalation (Horizontal)** | User tampers with URL identifier (`/users/2`) to view another profile | Server-side boundary check verifies `current_user.id == target_user_id` unless the requester possesses the `admin` role. |
| **Administrative Self-Lockout** | Admin inadvertently removes their own admin role or disables their own account | Route guards prevent an administrator from demoting or disabling their own active user record. |
| **Account Compromise via Inactive State** | User account flagged for security reasons continues operating | `login_required` checks `user.is_active_account` on every request. Inactive sessions are immediately cleared with HTTP 403. |

---

## 3. Laboratory Password Policy

To instill defensive cybersecurity hygiene, VADL enforces a server-side password complexity policy on registration:
* **Minimum Length**: 10 characters (configurable via `PASSWORD_MIN_LENGTH`).
* **Character Diversity**: Must contain at least one uppercase letter (`[A-Z]`), one lowercase letter (`[a-z]`), one decimal digit (`[0-9]`), and one special symbol (`[!@#$%^&*(),.?":{}|<>\-_=+[\]\\/]`).
* **Cryptographic Storage**: Hashed via Werkzeug's `scrypt` implementation with salting. Plaintext passwords are never logged or stored.

---

## 4. Training Edition vs. Secured Edition Architecture (Phase 3 Implemented)

| Dimension | Vulnerable Training Edition (`/lab/vulnerable/*`) | Secured Reference Edition (`/lab/secure/*`) |
| :--- | :--- | :--- |
| **Availability** | Development and testing only (`ENABLE_VULNERABLE_LAB=True`). Disabled in production. | Always available across all runtime environments. |
| **SQL Queries** | Dynamic string interpolation (CWE-89), verbose database exceptions returned to client. | Bound parameters via SQLAlchemy (`:category`), no secret flags exposed. |
| **HTML Rendering** | Explicitly marked as `Markup()` to bypass Jinja auto-escaping (CWE-79). | Jinja automatic contextual escaping (`&lt;script&gt;`). |
| **Object Access** | Direct lookup by numeric ID without ownership validation (CWE-639). | Server-side identity validation (`record.owner_email == current_user.email`). |
| **HTTP Headers** | Security headers explicitly omitted (CWE-16, CWE-693). | Strict CSP, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy`. |
| **Data Scope** | Dedicated synthetic toy tables (`lab_products`, `lab_comments`, `lab_records`). | Uses authenticated user context; no cross-talk with production assets. |

---

## 5. Container & Runtime Hardening Controls

| Security Control | Implementation | Threat Mitigated |
| :--- | :--- | :--- |
| **Non-Root Execution** | `vadluser` (UID 10001) in Dockerfile | Container breakout to host root privileges |
| **Capability Dropping** | `cap_drop: [ALL]` in Compose | Unauthorized Linux kernel capability exploitation |
| **Privilege Escalation** | `security_opt: [no-new-privileges:true]` | Setuid/setgid privilege escalation within container |
| **Docker Socket Isolation** | No `/var/run/docker.sock` volume mounts | Docker daemon hijacking and host takeover |
| **Source Code Protection** | Application code copied into image; no writable host bind mounts | Host file tampering or malicious code injection into repo |
| **Resource Constraints** | Memory limit 512 MB, CPU limit 1.0 | Resource exhaustion denial-of-service (DoS) |
| **Payload Limiting** | `MAX_CONTENT_LENGTH = 1 MB` | Memory exhaustion via oversized HTTP requests |

---

## 6. Target Authorization & Out-of-Bounds Scanning Controls (Phase 3)

To ensure future scanning engines cannot be weaponized against arbitrary or external systems, Phase 3 establishes target registration controls:

1. **Administrative Only**: Target creation and authorization is restricted strictly to administrators via `/admin/lab/targets`. Security analysts and ordinary users receive `HTTP 403 Forbidden`.
2. **Strict Hostname Allowlist**: URLs must match predefined internal lab hostnames (`127.0.0.1`, `localhost`, `vadl-app`, `vadl-vulnerable`, `vadl-db`, `vadl-worker`).
3. **SSRF & Metadata IP Blocking**: Targets with cloud metadata IPs (`169.254.169.254`, `metadata.google.internal`), link-local addresses, or non-HTTP protocols are rejected during validation.
4. **Offline Lexical Validation**: Target registration performs pure URL/domain parsing without initiating network connections, outbound socket probes, or DNS lookups, eliminating SSRF vectors during registration.
5. **Production Safeguard**: If `FLASK_CONFIG=production` and `VADL_ENABLE_VULNERABLE_LAB=true` are configured simultaneously, application startup aborts immediately (`ValueError`).

---

## 7. Offensive Testing Engine Boundaries (Phase 4)

1. **Pre-Execution Authorization Guard**: Every assessment requires target re-validation (`is_authorized == True`) immediately prior to execution, preventing race-conditions if an administrator revokes target authorization while an assessment is queued.
2. **Execution Sandboxing & Timeouts**: Individual scenario adapters run in-process with strict per-test timeout budgets (`TEST_TIMEOUT_SECONDS = 5`) and overall maximum scenario count constraints (`MAX_SCENARIOS_PER_ASSESSMENT = 10`).
3. **Forensic Evidence Sanitization**: Captured HTTP requests, responses, and evaluation artifacts are filtered through `sanitize_text()` to scrub credentials, session cookies, and authorization tokens, then bounded to `MAX_EVIDENCE_BYTES = 4096`.

---

## 8. Defensive Controls & Verification Integrity (Phase 5)

1. **Anti-Tamper Status Safeguard**: Manual transitions to `status = 'VERIFIED'` are prohibited across both web forms and JSON APIs. A remediation record can transition to `VERIFIED` strictly through the automated verification service passing all primary defenses and functional regression checks.
2. **Defensive Regression Validation**: Verification does not merely re-check whether an exploit fails; it affirmatively tests that normal application behavior is preserved (valid search queries return products, plain text comments display uncorrupted, legitimate owners access their confidential records, Content-Type headers remain intact).
3. **Evidence Integrity Hashing**: Sanitized forensic evidence is digested using SHA-256 upon verification completion and stored in `remediations.evidence_sha256`. The hash is also recorded in the immutable `remediation_audit_events` log.
4. **Access Control**: Only users holding the `security_analyst` or `admin` role may view, create, manage, or verify remediation tracks. Ordinary users are forbidden (`HTTP 403`).

---

## 9. Automated Security Scanning & Tool Sandboxing (Phase 6)

1. **Zero Dynamic Command / Subprocess Injection**:
   - All external security tools (Bandit, pip-audit, OWASP ZAP) are executed via strictly validated subprocess parameter lists (`subprocess.run(args: list[str])`).
   - `shell=True` is prohibited throughout all scanner adapters, eliminating arbitrary shell command chaining or injection vulnerabilities.
   - User-supplied inputs cannot alter executable paths, arguments, or execution profiles.

2. **Scanner Target Containment & DAST Network Isolation**:
   - Dynamic scanning via OWASP ZAP is strictly restricted to approved, active targets registered in `lab_targets`.
   - Out-of-scope URLs, public IP addresses, cloud metadata addresses (`169.254.169.254`), and non-allowlisted domains are rejected prior to execution.
   - Dockerized ZAP executions attach exclusively to `vadl-isolated-network` (an internal, non-routable Docker bridge), preventing outbound probes or port scanning across external host networks.

3. **Execution Resource Budgeting & Timeouts**:
   - Every scan execution is constrained by a strict timeout budget (`SCAN_TIMEOUT_SECONDS = 120`).
   - Long-running or hanging scanner processes are forcibly terminated, updating the database status to `TIMED_OUT`.
   - Tool report file ingestion is bounded by `MAX_REPORT_BYTES = 1048576` (1 MB) to prevent out-of-memory denial-of-service conditions.

4. **Machine-Readable Report Storage & Path Traversal Protections**:
   - Raw scan reports are saved in dedicated storage `reports/scans/<uuid4>.json` outside web roots and static asset directories.
   - Report download endpoints verify canonical path boundaries using `Path.resolve()`, preventing directory traversal (`../`) attacks.

5. **Deduplication Engine & Evidence Sanitization**:
   - Scanner outputs undergo forensic credential sanitization (stripping tokens, passwords, cookies) and byte-truncation (maximum 2048 bytes).
   - Findings are deduplicated across sequential runs using deterministic SHA-256 fingerprints, maintaining historical continuity (`NEW`, `ACTIVE`, `RESOLVED`, `FALSE_POSITIVE`) without duplicating alerts.


