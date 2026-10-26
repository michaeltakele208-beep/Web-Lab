"""Bandit static application security testing (SAST) adapter for Python source code (Phase 6)."""

import json
import logging
import subprocess
import sys
from pathlib import Path
from typing import Any

from app.engine.evidence import sanitize_text, truncate_evidence
from app.scanner.adapters.base import (
    BaseScannerAdapter,
    RawFinding,
    ReportParsingError,
    ScanExecutionResult,
    ScannerError,
    ScannerExecutionError,
    ScannerTimeoutError,
    ToolNotAvailableError,
)
from app.scanner.semantics import ScannerType

logger = logging.getLogger("vadl.scanner.bandit")

# Default excluded paths during Bandit static code analysis
DEFAULT_EXCLUDES = ".venv,venv,reports,instance,migrations,__pycache__,.pytest_cache,.ruff_cache"


class BanditAdapter(BaseScannerAdapter):
    """Adapter for executing Bandit Python static analysis and parsing raw results."""

    scanner_type = ScannerType.BANDIT

    def detect_availability(self) -> tuple[bool, str | None, str | None]:
        """Detect Bandit tool presence and parse semantic version string."""
        try:
            res = subprocess.run(
                [sys.executable, "-m", "bandit", "--version"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if res.returncode == 0:
                output = (res.stdout or res.stderr).strip()
                # Parse first line, e.g. "bandit 1.8.3"
                first_line = output.splitlines()[0].strip() if output else ""
                version = first_line.split()[-1] if first_line else "unknown"
                return True, version, None
            return False, None, f"Bandit returned nonzero code: {res.returncode}"
        except FileNotFoundError:
            return False, None, "Python executable or Bandit module not found."
        except Exception as exc:
            return False, None, f"Detection error: {exc}"

    def execute_scan(
        self,
        *,
        scan_uuid: str,
        target_url: str | None = None,
        source_dir: str | None = None,
        profile: str = "baseline",
        timeout_seconds: int = 120,
        options: dict[str, Any] | None = None,
    ) -> ScanExecutionResult:
        """Execute a controlled Bandit static analysis scan over application code."""
        is_avail, version, reason = self.detect_availability()
        if not is_avail:
            raise ToolNotAvailableError(f"Bandit scanner is unavailable: {reason}")

        # Enforce safe source directory bounds
        target_path = (source_dir or "app").strip()
        target_p = Path(target_path).resolve()
        is_temp_audit = (
            "vadl_audit_" in str(target_p)
            or "tmp" in str(target_p).lower()
            or "temp" in str(target_p).lower()
        )
        if target_path != "app" and not target_path.startswith("app/") and not is_temp_audit:
            raise ScannerError(
                "Bandit scans are strictly restricted to the 'app' source directory."
            )
        if not target_p.exists():
            raise ScannerError(f"Target directory '{target_path}' does not exist on disk.")

        opts = options or {}
        excludes = opts.get("excludes", DEFAULT_EXCLUDES)

        reports_dir = Path("reports/scans")
        reports_dir.mkdir(parents=True, exist_ok=True)
        report_file = reports_dir / f"{scan_uuid}_bandit.json"

        cmd = [
            sys.executable,
            "-m",
            "bandit",
            "-r",
            target_path,
            "-f",
            "json",
            "-o",
            str(report_file),
            "-x",
            excludes,
        ]

        logger.info(f"Executing Bandit SAST scan on '{target_path}' (UUID: {scan_uuid}).")

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise ScannerTimeoutError(
                f"Bandit static analysis exceeded timeout of {timeout_seconds}s."
            ) from exc
        except Exception as exc:
            raise ScannerExecutionError(f"Failed to execute Bandit process: {exc}") from exc

        # Bandit returns:
        # 0: No issues found
        # 1: Issues found (normal completion for security scanners)
        # 2: Command-line or syntax error
        if proc.returncode not in (0, 1):
            err_msg = proc.stderr.strip() or f"Bandit exited with error code {proc.returncode}"
            logger.error(f"Bandit execution error: {err_msg}")
            raise ScannerExecutionError(f"Bandit execution failed: {err_msg}")

        if not report_file.exists():
            raise ReportParsingError("Bandit did not generate the expected JSON output artifact.")

        try:
            with open(report_file, encoding="utf-8") as f:
                raw_json = json.load(f)
        except json.JSONDecodeError as exc:
            raise ReportParsingError(f"Bandit output contains invalid JSON: {exc}") from exc

        raw_findings = self._parse_bandit_results(raw_json)

        return ScanExecutionResult(
            scanner_type=self.scanner_type,
            exit_code=proc.returncode,
            tool_version=version,
            tool_configuration={
                "source_dir": target_path,
                "excludes": excludes,
                "timeout_seconds": timeout_seconds,
            },
            raw_report_path=str(report_file),
            findings=raw_findings,
            stdout=proc.stdout or "",
            stderr=proc.stderr or "",
        )

    def _parse_bandit_results(self, data: dict[str, Any]) -> list[RawFinding]:
        """Transform Bandit JSON results into RawFinding structures."""
        results = data.get("results", [])
        findings: list[RawFinding] = []

        for item in results:
            test_id = item.get("test_id", "UNKNOWN")
            filename = item.get("filename", "")
            issue_text = item.get("issue_text", "")
            severity = item.get("issue_severity", "LOW")
            confidence = item.get("issue_confidence", "LOW")
            line_num = item.get("line_number")
            code_snippet = item.get("code", "")
            cwe = item.get("issue_cwe", {})
            cwe_id = f"CWE-{cwe.get('id')}" if cwe and cwe.get("id") else None

            # Sanitize code snippet
            sanitized_evidence = sanitize_text(code_snippet)
            bounded_evidence = truncate_evidence(sanitized_evidence, max_bytes=2048)

            # Check if this finding is within the deliberately vulnerable lab code
            is_lab = "lab_vulnerable" in filename or "vulnerable" in filename
            scenario_id = None
            if is_lab:
                if test_id == "B608" or "sql" in issue_text.lower():
                    scenario_id = "VADL-SQLI-001"
                elif (
                    test_id in ("B703", "B308")
                    or "xss" in issue_text.lower()
                    or "markup" in issue_text.lower()
                ):
                    scenario_id = "VADL-XSS-001"

            remediation = self._derive_remediation(test_id, issue_text, is_lab)

            finding = RawFinding(
                tool_finding_id=test_id,
                title=f"Bandit {test_id}: {issue_text[:120]}",
                description=issue_text,
                raw_severity=severity,
                raw_confidence=confidence,
                category=item.get("test_name", "Static Python Code Security"),
                cwe_id=cwe_id,
                owasp_category=self._derive_owasp(test_id, cwe_id),
                target_component=filename,
                file_path=filename,
                line_number=line_num,
                evidence_snippet=bounded_evidence,
                remediation_guidance=remediation,
                advisory_url=item.get("more_info"),
                extra_metadata={
                    "is_lab_scenario": is_lab,
                    "scenario_id": scenario_id,
                    "test_name": item.get("test_name"),
                },
            )
            findings.append(finding)

        return findings

    @staticmethod
    def _derive_remediation(test_id: str, issue_text: str, is_lab: bool) -> str:
        """Provide prescriptive remediation advice based on Bandit test ID."""
        if is_lab:
            return (
                "Notice: This is an intentional security vulnerability in the VADL training lab edition. "
                "Consult the corresponding secure reference implementation in 'app/routes/lab_secure.py' "
                "to inspect hardened defensive controls."
            )
        remediations = {
            "B608": "Use parameterized queries or ORM bound parameters instead of string formatting.",
            "B101": "Do not rely on 'assert' statements for security-sensitive logic in production code.",
            "B104": "Bind services to specific loopback addresses (127.0.0.1) rather than all interfaces (0.0.0.0).",
            "B105": "Avoid hardcoded passwords or secrets; source credentials from environment variables.",
            "B110": "Log specific exceptions rather than using bare 'try...except: pass' constructs.",
            "B308": "Sanitize and contextually escape user-controlled inputs before injecting into HTML markups.",
            "B703": "Avoid using markupsafe or Markup() on untrusted user strings.",
        }
        return remediations.get(
            test_id,
            f"Review code around line to resolve static analysis finding: {issue_text}",
        )

    @staticmethod
    def _derive_owasp(test_id: str, cwe_id: str | None) -> str:
        """Map Bandit finding to OWASP Top 10 category."""
        if test_id in ("B608",) or cwe_id == "CWE-89":
            return "A03:2021-Injection"
        if test_id in ("B703", "B308") or cwe_id == "CWE-79":
            return "A03:2021-Injection"
        if test_id in ("B105", "B106", "B107"):
            return "A07:2021-Identification and Authentication Failures"
        if test_id in ("B104", "B110"):
            return "A05:2021-Security Misconfiguration"
        return "A04:2021-Insecure Design"
