# VADL Security Testing & Evaluation Methodology

This document establishes the standardized security methodology employed across the **Vulnerability Assessment and Defense Lab (VADL)** platform.

---

## 1. Authorized Testing Bounds & Ethics

All security testing within VADL is governed by strict authorization controls:

1. **Explicit Target Allowlisting**:
   - Only targets registered in the database with `LabTarget.is_authorized=True` can be selected for scanning or offensive assessment.
   - Hostname validation enforces loopback addresses (`127.0.0.1`, `localhost`) and designated container subnets (`vadl-*`).
   - Private cloud metadata addresses (`169.254.169.254`), non-HTTP schemes, and arbitrary external domains are rejected by `validate_lab_target_url()`.
2. **Defensive Research Intent**:
   - Attacks are conducted solely against synthetic test data.
   - Attack payloads are designed for non-destructive verification (e.g., `' OR '1'='1` for SQL injection query alteration, `<span id="poc">` for XSS proof of concept).

---

## 2. Multi-Tier Assessment Toolkit

VADL utilizes complementary testing techniques to achieve multi-perspective coverage:

| Assessment Class | Tool / Adapter | Detection Focus | Advantages | Limitations |
|---|---|---|---|---|
| **Dynamic Application Security Testing (DAST)** | **OWASP ZAP** (`ZapAdapter`) | Runtime HTTP inspection, missing headers, cookie security, crawlable endpoints. | Evaluates live running application; zero false positives on HTTP headers. | Misses unlinked API endpoints or complex multi-stage flows without recorded contexts. |
| **Static Application Security Testing (SAST)** | **Bandit** (`BanditAdapter`) | Python source code AST analysis, dangerous built-in usage, raw SQL string formatting. | 100% code branch visibility; detects latent flaws before deployment. | Cannot verify runtime reachability or context awareness. |
| **Software Composition Analysis (SCA)** | **pip-audit** (`PipAuditAdapter`) | Known third-party CVEs in pinned Python packages (`requirements.txt`). | Instant matching against PyPI and OSV advisory databases. | Zero-day flaws or unvetted private packages are not flagged. |
| **Scenario-Specific Offensive Adapters** | **VADL Engine** (`sqli_adapter`, `xss_adapter`, etc.) | Empirical verification of specific OWASP scenario attack payloads. | Deterministic, highly accurate verification of specific flaws. | Tests modeled attack patterns only; does not replace manual exploratory testing. |

---

## 3. Finding Lifecycle & Severity Taxonomy

Findings discovered by scanners or assessment adapters are normalized into standard lifecycle states:

```
[ NEW ] ──> [ ACTIVE ] ──> [ RESOLVED ]
   │
   └──> [ FALSE_POSITIVE ]
```

- **`NEW`**: Discovered for the first time by a scanner or adapter in the current scan run.
- **`ACTIVE`**: Re-observed in subsequent scans; vulnerability persists unmitigated.
- **`RESOLVED`**: Previously active finding that was no longer observed in the latest scan or certified by the remediation verification engine.
- **`FALSE_POSITIVE`**: Manually audited by a security analyst and marked non-exploitable or intentional laboratory design.

### Severity Classification
- **`CRITICAL`**: Unauthenticated remote code execution, database compromise via unparameterized SQL injection, or full horizontal/vertical administrative takeover.
- **`HIGH`**: Persistent Cross-Site Scripting (Stored XSS) in high-privilege contexts, direct object references allowing sensitive data leakage.
- **`MEDIUM`**: Missing critical HTTP security headers (e.g., Content-Security-Policy), permissive CORS configurations, informational leaks.
- **`LOW`**: Information disclosure of non-sensitive software versions or verbose error banners.
- **`INFORMATIONAL`**: Best-practice recommendations and diagnostic telemetry.

---

## 4. Remediation Verification Workflow

VADL strictly enforces the **Principle of Empirical Verification**:

> [!IMPORTANT]
> **Manual Assertions Are Not Proof**: An engineer or analyst cannot simply mark a vulnerability as "fixed" in a database or ticket. The system requires an automated regression check executed against the secure edition.

### Verification Criteria
To achieve `VERIFIED` status:
1. **Attack Neutralization**: The exact payload that previously triggered the vulnerability must be submitted against the secure edition, and the response must confirm that the attack was neutralized (e.g., SQL input treated as literal, XSS encoded as HTML entities, IDOR rejected with HTTP 403).
2. **Functional Preservation**: Benign user operations must continue functioning normally without errors (e.g., benign search queries still return valid catalog items).
3. **Cryptographic Integrity Digest**: The verification response evidence is hashed using SHA-256 (`evidence_sha256`) and recorded in the audit log to provide non-repudiation and prevent historical tampering.

---

## 5. Analytical Limitations & Caveats

1. **Negative Assertion Limitation**: A scan reporting `0 Findings` indicates only that the configured rules did not trigger on the inspected paths. It does NOT mathematically prove an application is bug-free.
2. **Scan Comparison Conclusiveness**: Differential trend comparisons between two scans are conclusive only when both runs completed normally against the same target. If either run was cancelled, timed out, or encountered execution errors, the comparison is marked `is_conclusive=False` and analytical caveats are surfaced.
