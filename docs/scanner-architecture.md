# Scanner Integration Architecture & Security Engineering

This document details the software architecture, adapter design patterns, sandbox invariants, and security controls powering the **Vulnerability Assessment and Defense Lab (VADL)** automated scanning subsystem.

---

## 1. Subsystem Architecture Overview

The scanning integration layer adheres to strict separation of concerns, decoupling web presentation handlers from command execution, normalization algorithms, and evidence storage.

```mermaid
flowchart TD
    UI[Analyst Web UI / REST API] -->|Scan Request + CSRF| RouteHandler[routes/scans.py]
    RouteHandler -->|Validate Role & CSRF| Orchestrator[scanner/orchestrator.py]
    
    subgraph Security Guards & Verification
        Orchestrator -->|Enforce Target Allowlist| TargetGuard[lab/target_validator.py]
        Orchestrator -->|Check Tool Availability| ToolRegistry[scanner/adapters/registry.py]
        Orchestrator -->|Validate Target Authorization| DBTarget[(LabTarget State)]
    end
    
    subgraph Scanner Adapters
        ToolRegistry -->|Instantiate Adapter| Adapters{Adapter Type}
        Adapters -->|SAST: app/ source tree| Bandit[adapters/bandit_adapter.py]
        Adapters -->|SCA: requirements.txt| PipAudit[adapters/pip_audit_adapter.py]
        Adapters -->|DAST: vadl-isolated-network| ZAP[adapters/zap_adapter.py]
    end
    
    subgraph Execution & Normalization
        Bandit -->|Subprocess (no shell)| BanditCLI[bandit executable]
        PipAudit -->|Subprocess (no shell)| PipAuditCLI[pip-audit executable]
        ZAP -->|Docker (non-root)| ZAPContainer[owasp/zap2docker-weekly]
        
        BanditCLI --> RawJSON[Tool Output Parser]
        PipAuditCLI --> RawJSON
        ZAPContainer --> RawJSON
        
        RawJSON -->|Sanitize & Truncate| Normalizer[NormalizedFinding Factory]
        Normalizer -->|SHA-256 Fingerprint| DedupEngine[Deduplication Engine]
    end
    
    subgraph Persistence & Audit
        DedupEngine --> DB[(SQLite Database)]
        Orchestrator --> FileSystem[reports/scans/uuid.json]
        Orchestrator --> DBAudit[(ScanAuditEvent)]
    end
```

---

## 2. Adapter Specification (`BaseScannerAdapter`)

All automated scanner adapters inherit from `BaseScannerAdapter` and implement four core methods:

```python
class BaseScannerAdapter(ABC):
    @property
    @abstractmethod
    def scanner_type(self) -> ScannerType: ...

    @abstractmethod
    def detect_availability(self) -> tuple[bool, str | None, str | None]: ...

    @abstractmethod
    def run_scan(self, config: dict[str, Any]) -> ScanExecutionResult: ...

    @abstractmethod
    def parse_report(self, raw_report: str) -> list[RawFinding]: ...
```

### Registered Tool Adapters:
1. **`BanditAdapter` (`ScannerType.BANDIT`)**:
   - Analyzes application Python code (`app/` tree).
   - Excludes virtual environments (`.venv`), tests (`tests/`), reports (`reports/`), and migrations (`migrations/`).
   - Identifies deliberate training flaws (e.g., intentional SQL injection in `app/lab/vulnerable_routes.py`) and maps them to Scenario IDs (e.g., `VADL-SQLI-001`).
2. **`PipAuditAdapter` (`ScannerType.PIP_AUDIT`)**:
   - Inspects pinned runtime dependencies in `requirements.txt`.
   - Queries vulnerability databases (OSV, PyPA) without network execution inside untrusted contexts.
   - Extracts affected package name, installed version, CVE/GHSA identifiers, and recommended upgrade target.
3. **`ZapAdapter` (`ScannerType.ZAP`)**:
   - Executes dynamic security tests against registered, local lab targets.
   - Restricts execution strictly to `vadl-isolated-network` bridge.
   - Enforces passive baseline scanning by default (`zap-baseline.py`).
   - Rejects any URL not resolving to `127.0.0.1`, `localhost`, or `vadl-*` container hostnames.

---

## 3. Sandboxing & Isolation Guarantees

Automated vulnerability testing tools can inadvertently cause denial-of-service, unintended network egress, or remote code execution if misconfigured. VADL enforces five layers of isolation:

### 1. Zero Arbitrary Command Injection
* `subprocess.run()` is called exclusively with explicit list arguments (`args: list[str]`).
* `shell=True` is prohibited throughout the entire scanner codebase.
* User-provided strings (such as target paths or URL parameters) are never passed to shell interpreters.

### 2. Lexical & Runtime Target Containment
* DAST scans require pre-existing registration in `lab_targets` table.
* The target URL must pass strict regex allowlisting via `validate_lab_target_url()`:
  - Scheme must be `http` or `https`.
  - Host must be `127.0.0.1`, `localhost`, or match `^vadl-[a-z0-9_-]+$`.
  - External domains, public IPs, cloud metadata addresses (`169.254.169.254`), and loopback variations (`0.0.0.0`) are immediately rejected with HTTP 400.

### 3. Container Isolation (`vadl-isolated-network`)
* When ZAP executes in Docker:
  - `network_mode` is set to `vadl-isolated-network` (an internal, non-routable Docker bridge).
  - The container runs as non-root user `zap` (`uid 1000`).
  - Read-only filesystem mounts are enforced for test configurations.

### 4. Path Traversal Safeguards
* Stored machine-readable reports are named using UUID4 tokens: `reports/scans/<uuid4>.json`.
* The report download endpoint enforces canonical path resolution (`Path(path).resolve()`), verifying that requested files reside strictly inside the `reports/scans/` root directory.
* Direct directory listings and parent traversal (`..`) are blocked.

### 5. Execution Timeouts & Resource Bounds
* Every scan execution subprocess is bounded by `SCAN_TIMEOUT_SECONDS` (default: 120 seconds).
* Hanging scans are automatically terminated, transitioning state to `ScanLifecycle.TIMED_OUT`.
* Maximum report size is capped at 1 MB (`MAX_REPORT_BYTES = 1048576`) to prevent memory exhaustion attacks.

---

## 4. Audit Trail & Verification Logs

Every scanning action produces immutable audit events stored in `scan_audit_events`:

| Event Type | Trigger | Logged Details |
| :--- | :--- | :--- |
| `SCAN_INITIATED` | Scan started by analyst or API | Initiator ID, Scanner Type, Profile, Target/Path |
| `TARGET_VERIFIED` | Target authorization & allowlist check | Target URL, Authorized Status |
| `SCAN_COMPLETED` | Execution finished successfully | Duration, Raw Findings Count, Status |
| `FINDINGS_NORMALIZED` | Processing and deduplication done | New vs Active vs Resolved counts |
| `SCAN_FAILED` | Scanner execution or parse error | Error message, execution return code |
| `SCAN_TIMED_OUT` | Subprocess exceeded timeout | Timeout threshold (seconds) |
