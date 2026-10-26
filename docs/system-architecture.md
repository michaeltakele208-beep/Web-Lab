# VADL System Architecture & Component Interaction

## 1. High-Level Architectural Overview

The **Vulnerability Assessment and Defense Lab (VADL)** is organized into decoupled layers following the Flask application factory pattern:

```mermaid
flowchart TD
    Client["Student / Analyst / Admin Browser"] -->|HTTPS / Loopback| WebLayer["Web Layer & Security Middleware"]
    
    subgraph WebLayer["Web Layer & Security Middleware"]
        AuthGuard["Auth & Session Guard (Werkzeug scrypt, Session Renewal)"]
        CSRFGuard["CSRF Token Middleware (HMAC comparison)"]
        RBACGuard["RBAC Authorization Guard (user, analyst, admin)"]
    end

    AuthGuard --> RoutingEngine{"Routing Engine"}

    subgraph LabEnvironments["Isolated Lab Environments"]
        direction TB
        VulnApp["Vulnerable Blueprint (/lab/vulnerable)<br/>• Unparameterized SQL<br/>• Raw Unescaped HTML (Markup)<br/>• Unchecked Object IDs<br/>• Missing Security Headers"]
        SecureApp["Secure Reference Blueprint (/lab/secure)<br/>• Parameterized Bindings (:cat)<br/>• Contextual Auto-Escaping<br/>• Session Ownership Validation<br/>• Enforced Security Headers"]
        ToyDB[("Synthetic Toy Datasets<br/>• lab_products<br/>• lab_comments<br/>• lab_records")]
        VulnApp --> ToyDB
        SecureApp --> ToyDB
    end

    subgraph SecurityEngines["Automated Security Engines"]
        OffEngine["Offensive Assessment Engine<br/>• Scenario Adapters (SQLi, XSS, IDOR, Headers)<br/>• Target Authorization Guard"]
        ScanEngine["Multi-Tool Scanner Integration<br/>• Bandit SAST Adapter<br/>• pip-audit SCA Adapter<br/>• OWASP ZAP DAST Adapter"]
        RemedEngine["Remediation & Verification Engine<br/>• Automated Regression Verification<br/>• SHA-256 Evidence Hashing"]
    end

    subgraph PresentationAndReporting["Presentation & Reporting Subsystem"]
        Dashboard["Operations Dashboard (Live SQL Aggregates)"]
        PDFGen["Pure-Python PDF Generator (ReportLab NumberedCanvas)"]
        JSONGen["Machine-Readable JSON Generator"]
        Comparator["Scan Comparison & Trend Service"]
    end

    RoutingEngine --> LabEnvironments
    RoutingEngine --> SecurityEngines
    RoutingEngine --> PresentationAndReporting

    subgraph StorageLayer["Database & Persistence Layer (SQLAlchemy 2.0 / Alembic)"]
        CoreDB[("Users & Roles<br/>Lab Targets<br/>Security Scans & Normalized Findings<br/>Assessments & Test Results<br/>Remediations & Verification Digests<br/>Security Reports & Download Audits")]
    end

    SecurityEngines --> StorageLayer
    PresentationAndReporting --> StorageLayer
```

---

## 2. Separation of Vulnerable & Secure Lab Applications

To ensure complete safety, the vulnerable training application is strictly isolated from production application infrastructure:

1. **Independent Blueprint Namespaces**:
   - `/lab/vulnerable/*`: Contains intentional vulnerabilities operating solely over synthetic datasets (`lab_products`, `lab_comments`, `lab_records`).
   - `/lab/secure/*`: Implements industry-standard mitigations (e.g., SQLAlchemy `:param` binding, Jinja auto-escaping, session-bound ownership guards).
2. **Environment Configuration Safety Gate**:
   - `check_lab_enabled()` executes before every request to `/lab/vulnerable/*`.
   - If `ENABLE_VULNERABLE_LAB` is `False` (the default in production), the blueprint returns HTTP 404.
   - If `ENABLE_VULNERABLE_LAB=true` is set alongside `FLASK_CONFIG=production`, the application factory aborts startup immediately with `ValueError`.
3. **Synthetic Dataset Isolation**:
   - Toy database tables do not contain real user credentials, live session identifiers, or administrative secrets.
   - Flags used in testing (e.g., `CONFIDENTIAL_LAB_FLAG{vadl_sqli_success}`) are synthetic strings created specifically for validation.

---

## 3. Offensive Assessment & Target Authorization Flow

```mermaid
sequenceDiagram
    autonumber
    actor Analyst as Security Analyst
    participant Web as Web Console / API
    participant Guard as Target Authorization Guard
    participant Engine as Assessment Engine
    participant Adapter as Scenario Test Adapter
    participant Lab as Lab Target (Vulnerable / Secure)
    participant DB as Persistence & Audit Log

    Analyst->>Web: Launch Assessment(Target ID #1, Scenarios=[SQLI, XSS])
    Web->>Guard: Validate Target Authorization(Target ID #1)
    alt Target Unauthorized or External URL
        Guard-->>Web: Reject Request (HTTP 400 / 403)
        Web-->>Analyst: "Target is not authorized for assessment."
    else Target Authorized Loopback / Isolated Container
        Guard->>Engine: Authorize Execution
        Engine->>DB: Create Assessment(Status="RUNNING")
        loop For Each Selected Scenario
            Engine->>Adapter: Execute Payload Test Case
            Adapter->>Lab: Dispatch HTTP Probe (e.g. category="' OR '1'='1")
            Lab-->>Adapter: HTTP Response Body & Headers
            Adapter->>Adapter: Evaluate Response (Exploit vs Neutralized)
            Adapter->>Adapter: Sanitize & Truncate Evidence (<= 2048 bytes)
            Adapter-->>Engine: TestResult(Outcome, SanitizedEvidence)
            Engine->>DB: Commit TestResult
        end
        Engine->>DB: Update Assessment(Status="COMPLETED")
        Engine-->>Web: Assessment Completed
        Web-->>Analyst: Render Assessment Results & Telemetry
    end
```

---

## 4. Remediation & Automated Verification Workflow

The defensive remediation lifecycle prevents manual or unsubstantiated claims of vulnerability resolution:

```mermaid
stateDiagram-v2
    [*] --> OPEN: Finding Discovered
    OPEN --> IN_PROGRESS: Analyst Assigned & Mitigation Begun
    IN_PROGRESS --> READY_FOR_VERIFICATION: Hardened Code Deployed
    
    state "Automated Verification Execution" as VerifyStep {
        READY_FOR_VERIFICATION --> VerificationRunning: Trigger Automated Verification
        VerificationRunning --> RunRegression: Dispatch Attack Payload against Secure Edition
        RunRegression --> EvaluateBehavior: Verify Exploit Neutralized AND Functionality Intact
    }

    EvaluateBehavior --> VERIFIED: Exploit Neutralized (SHA-256 Evidence Sealed)
    EvaluateBehavior --> FAILED: Exploit Succeeded or Regressed
    EvaluateBehavior --> INCONCLUSIVE: Ambiguous or Timeout

    FAILED --> REOPENED: Remediation Defective
    REOPENED --> IN_PROGRESS: Further Code Hardening
    VERIFIED --> [*]: Defense Empirically Certified
```

---

## 5. Security Scanner Normalization Architecture

When automated tools (Bandit, pip-audit, OWASP ZAP) execute, their raw tool outputs are normalized into a canonical schema before database insertion:

1. **Tool Availability Detection**:
   - `detect_availability()` queries tool CLI binaries (`sys.executable -m bandit`, `pip-audit --version`, `docker info`).
   - If a tool is unavailable, structured execution errors are returned; scan results are never fabricated.
2. **Canonical Finding Schema (`NormalizedFinding`)**:
   - Mapped to standard severities (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFORMATIONAL`).
   - Mapped to CWE identifiers (e.g., `CWE-89`, `CWE-79`) and OWASP categories (`A03:2021-Injection`).
   - Technical evidence sanitized of terminal ANSI codes and truncated.
3. **Deterministic Deduplication**:
   - SHA-256 fingerprint generated from `(scanner_name, tool_finding_id, target_component, cwe_id)`.
   - Prevents duplicate findings across recurring scan runs; existing findings transition from `NEW` to `ACTIVE`, while resolved findings transition to `RESOLVED`.
