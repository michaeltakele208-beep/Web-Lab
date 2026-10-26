# Common Findings Normalization Schema & Deduplication Engine

The **Vulnerability Assessment and Defense Lab (VADL)** integrates heterogeneous automated security scanning tools (SAST, SCA, and DAST) into a unified findings data model. This document defines the canonical schema, severity/confidence mappings, deduplication algorithms, and status lifecycle.

---

## 1. Finding Schema Specification

All scanner adapters normalize tool-specific outputs into the `NormalizedFinding` model before database persistence.

### Data Model Fields

| Field Name | Type | Nullable | Description |
| :--- | :--- | :--- | :--- |
| `id` | `Integer` | No | Auto-incrementing primary key. |
| `scan_id` | `Integer` | No | Foreign key referencing the parent `SecurityScan`. |
| `target_id` | `Integer` | Yes | Foreign key referencing `LabTarget` (null for SAST/SCA repository scans). |
| `title` | `String(255)` | No | Concise summary of the vulnerability. |
| `description` | `Text` | Yes | Detailed technical explanation of the identified risk. |
| `scanner_type` | `String(32)` | No | Originating scanner: `bandit`, `pip_audit`, or `zap`. |
| `severity` | `String(32)` | No | Normalized severity level: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `INFORMATIONAL`. |
| `confidence` | `String(32)` | No | Normalized confidence rating: `CONFIRMED`, `HIGH`, `MEDIUM`, `LOW`, or `EXPERIMENTAL`. |
| `status` | `String(32)` | No | Finding lifecycle status: `NEW`, `ACTIVE`, `RESOLVED`, or `FALSE_POSITIVE`. |
| `fingerprint` | `String(64)` | No | Deterministic SHA-256 fingerprint for cross-scan tracking and deduplication. Indexed. |
| `cwe_id` | `String(32)` | Yes | Common Weakness Enumeration identifier (e.g. `CWE-89`, `CWE-79`). |
| `owasp_category`| `String(64)` | Yes | OWASP Top 10 category mapping (e.g. `A03:2021-Injection`). |
| `vulnerability_identifier` | `String(128)` | Yes | Tool-specific identifier or CVE (e.g., `CVE-2023-32681`, `B608`, `40012`). |
| `remediation_advice` | `Text` | Yes | Concrete, actionable guidance for resolving the finding. |
| `evidence_snippet` | `Text` | Yes | Sanitized, truncated code or HTTP request/response excerpt demonstrating the finding. |
| `raw_details` | `JSON` | Yes | Complete unstructured findings metadata from the tool output. |
| `is_lab_scenario`| `Boolean` | No | True if finding matches an intentional VADL training vulnerability scenario. |
| `scenario_id` | `String(64)` | Yes | Scenario ID if intentional (e.g., `VADL-SQLI-001`). |
| `first_detected_at` | `DateTime` | No | Timestamp of the first scan that detected this fingerprint. |
| `last_detected_at`  | `DateTime` | No | Timestamp of the most recent scan that detected this fingerprint. |
| `resolved_at` | `DateTime` | Yes | Timestamp when the vulnerability was verified resolved in a subsequent scan. |

---

## 2. Severity & Confidence Mapping Matrix

Different security tools use differing scales for severity and confidence. The scanner layer maps each tool's terminology into standard VADL ratings.

### Severity Normalization

| Standard Severity | Bandit SAST | pip-audit SCA | OWASP ZAP DAST |
| :--- | :--- | :--- | :--- |
| **`CRITICAL`** | *(N/A)* | CVSS Score $\ge$ 9.0 | *(N/A)* |
| **`HIGH`** | `HIGH` | CVSS Score 7.0 – 8.9 | Risk `3` (High) |
| **`MEDIUM`** | `MEDIUM` | CVSS Score 4.0 – 6.9 | Risk `2` (Medium) |
| **`LOW`** | `LOW` | CVSS Score 0.1 – 3.9 | Risk `1` (Low) |
| **`INFORMATIONAL`** | `UNDEFINED` | Unrated advisory / Missing CVSS | Risk `0` (Informational) |

### Confidence Normalization

| Standard Confidence | Bandit SAST | pip-audit SCA | OWASP ZAP DAST |
| :--- | :--- | :--- | :--- |
| **`CONFIRMED`** | *(N/A)* | Verified published CVE / OSV match | *(N/A)* |
| **`HIGH`** | `HIGH` | *(N/A)* | Confidence `3` (High) |
| **`MEDIUM`** | `MEDIUM` | *(N/A)* | Confidence `2` (Medium) |
| **`LOW`** | `LOW` | *(N/A)* | Confidence `1` (Low) |
| **`EXPERIMENTAL`** | `UNDEFINED` | *(N/A)* | Confidence `0` (False Positive) |

---

## 3. Fingerprint Generation & Deduplication Engine

To accurately track findings across sequential scans without duplicate alert storms, VADL calculates a deterministic 64-character hexadecimal SHA-256 fingerprint:

$$\text{Fingerprint} = \text{SHA-256}\left(\text{scanner\_type} \parallel \text{title} \parallel \text{cwe\_id} \parallel \text{vuln\_id} \parallel \text{target\_or\_source}\right)$$

### Canonical Normalization Inputs:
1. `scanner_type`: lowercase string (`bandit`, `pip_audit`, `zap`).
2. `title`: trimmed, lowercase finding title.
3. `cwe_id`: uppercase standardized CWE ID (e.g. `CWE-89`), or empty string.
4. `vulnerability_identifier`: canonical rule/advisory ID (e.g. `B608`, `GHSA-xxxx`), or empty string.
5. `target_or_source`: registered target URL for DAST, or target directory/path for SAST/SCA.

### State Transition Lifecycle

```
       [ Scan Run #1 ]
              │
       (New Finding) ──────> [ Status: NEW ]
                                   │
       [ Scan Run #2 ]             │
      (Same Fingerprint) ──────────┴─────> [ Status: ACTIVE ]
                                                  │
       [ Scan Run #3 ]                            │
     (Fingerprint Absent) ────────────────────────┴─────> [ Status: RESOLVED ]
```

1. **`NEW`**: Assigned when a fingerprint is encountered for the first time in the database. `first_detected_at` and `last_detected_at` are set to current timestamp.
2. **`ACTIVE`**: If a subsequent scan detects the same fingerprint, the new finding record is linked, `first_detected_at` is preserved from historical records, and status is marked `ACTIVE`.
3. **`RESOLVED`**: When a target or source tree is rescanned and a previously `NEW` or `ACTIVE` finding is no longer detected, its status updates to `RESOLVED` and `resolved_at` is recorded.
4. **`FALSE_POSITIVE`**: Analysts can triage non-issues, marking the status `FALSE_POSITIVE` with audit log preservation.

---

## 4. Evidence Sanitization & Redaction

Evidence collected by scanning adapters (HTTP requests, headers, SQL fragments, package outputs) is scrubbed prior to persistence:
1. **Credential Sanitization**: High-entropy API keys, passwords, session cookies, and JWT tokens are replaced with redaction tokens (`[REDACTED_PASSWORD]`, `[REDACTED_COOKIE]`, `[REDACTED_TOKEN]`).
2. **Bounded Output Size**: Evidence snippets are hard-capped at 2048 bytes to prevent database bloat and denial-of-service via oversized payloads.
3. **Machine-Readable Storage**: Full, raw scan outputs are stored in `reports/scans/<uuid>.json` outside the web root, with filesystem permissions restricted to the running service account.
