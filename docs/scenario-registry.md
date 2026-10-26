# VADL Vulnerability Scenario Registry

## 1. Registry Architecture & Metadata Specification

The **VADL Scenario Registry** (`app/lab/registry.py`) defines a structured, programmatic catalog of all vulnerability scenarios supported in the laboratory. Each scenario is instantiated as an immutable `VulnerabilityScenario` dataclass with standardized security metadata.

### Data Model Schema

| Field | Type | Description |
| :--- | :--- | :--- |
| `id` | `str` | Unique scenario identifier (e.g. `VADL-SQLI-001`). |
| `name` | `str` | Human-readable title of the scenario. |
| `category` | `str` | Security classification (e.g., `Injection`, `Broken Access Control`). |
| `cwe_id` | `str` | Common Weakness Enumeration identifier (e.g., `CWE-89`). |
| `owasp_category` | `str` | OWASP Top 10 2021 mapping (e.g., `A03:2021-Injection`). |
| `severity` | `str` | Standard severity rating (`Low`, `Medium`, `High`, `Critical`). |
| `description` | `str` | Technical description of the flaw mechanism. |
| `vulnerable_endpoint` | `str` | Path to the deliberately vulnerable lab endpoint. |
| `secure_endpoint` | `str` | Path to the hardened reference endpoint. |
| `expected_vulnerable_behavior` | `str` | Observable indicator of vulnerability during testing. |
| `expected_secure_behavior` | `str` | Observable indicator of defense during regression testing. |
| `remediation` | `str` | Prescribed defensive engineering solution. |

---

## 2. Registered Laboratory Scenarios

### Scenario 1: VADL-SQLI-001
* **Name**: Unsafe SQL Query Construction in Product Category Search
* **Category**: Injection
* **CWE**: CWE-89 (Improper Neutralization of Special Elements used in an SQL Command)
* **OWASP**: A03:2021-Injection
* **Severity**: High
* **Vulnerable Endpoint**: `/lab/vulnerable/sqli`
* **Secure Endpoint**: `/lab/secure/sqli`
* **Vulnerable Behavior**: Supplying `hardware' OR '1'='1` alters the SQL AST, exposing restricted products and flags.
* **Secure Behavior**: Query parameters are bound via `:category`, returning 0 matches for unknown string literals.
* **Remediation**: Use parameterized queries and parameter binding. User input must never be directly interpolated into SQL strings.

---

### Scenario 2: VADL-XSS-001
* **Name**: Unescaped HTML Rendering in Peer Discussion Comments
* **Category**: Cross-Site Scripting
* **CWE**: CWE-79 (Improper Neutralization of Input During Web Page Generation)
* **OWASP**: A03:2021-Injection
* **Severity**: Medium
* **Vulnerable Endpoint**: `/lab/vulnerable/xss`
* **Secure Endpoint**: `/lab/secure/xss`
* **Vulnerable Behavior**: Injected `<script>` and `<img>` tags execute JavaScript in the victim browser DOM.
* **Secure Behavior**: Jinja2 contextual escaping renders tags safely as `&lt;script&gt;`.
* **Remediation**: Enforce automatic contextual HTML entity encoding; never mark untrusted user content as `Markup()`.

---

### Scenario 3: VADL-AC-001
* **Name**: Insecure Direct Object Reference (IDOR) in Diagnostic Report Lookup
* **Category**: Broken Access Control
* **CWE**: CWE-639 (Authorization Bypass Through User-Controlled Key)
* **OWASP**: A01:2021-Broken Access Control
* **Severity**: High
* **Vulnerable Endpoint**: `/lab/vulnerable/records/<id>`
* **Secure Endpoint**: `/lab/secure/records/<id>`
* **Vulnerable Behavior**: Authenticated users can view diagnostic records belonging to other users by changing numeric ID parameters in the URL.
* **Secure Behavior**: Server-side authorization check compares `record.owner_email` against the current authenticated user identity, returning `HTTP 403 Forbidden` on mismatch.
* **Remediation**: Implement mandatory server-side ownership checks before returning object representations.

---

### Scenario 4: VADL-HEADERS-001
* **Name**: Missing Defensive Security and Frame Control Headers
* **Category**: Security Misconfiguration
* **CWE**: CWE-16 (Configuration), CWE-693 (Protection Mechanism Failure)
* **OWASP**: A05:2021-Security Misconfiguration
* **Severity**: Low
* **Vulnerable Endpoint**: `/lab/vulnerable/headers`
* **Secure Endpoint**: `/lab/secure/headers`
* **Vulnerable Behavior**: The HTTP response lacks `Content-Security-Policy`, `X-Content-Type-Options`, and `X-Frame-Options`, allowing clickjacking and MIME sniffing.
* **Secure Behavior**: Defensive headers are explicitly sent, restricting framing (`frame-ancestors 'none'`, `X-Frame-Options: DENY`) and disabling content sniffing (`nosniff`).
* **Remediation**: Configure global HTTP response middleware or reverse proxy configurations to enforce defensive security headers.

---

## 3. Programmatic Usage in Assessments

Security analysts can inspect registered scenarios through the `/assessments` console or programmatically via `app.lab.registry`:

```python
from app.lab.registry import get_all_scenarios, get_scenario

# Retrieve all registered scenarios
all_scenarios = get_all_scenarios()

# Retrieve specific scenario by ID
sqli_meta = get_scenario("VADL-SQLI-001")
print(f"{sqli_meta.name} -> CWE: {sqli_meta.cwe_id}")
```
