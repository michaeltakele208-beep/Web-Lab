"""pip-audit software composition analysis (SCA) dependency vulnerability adapter (Phase 6)."""

import json
import logging
import subprocess
import sys
from pathlib import Path
from typing import Any

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

logger = logging.getLogger("vadl.scanner.pip_audit")


class PipAuditAdapter(BaseScannerAdapter):
    """Adapter for running pip-audit against declared application requirements."""

    scanner_type = ScannerType.PIP_AUDIT

    def detect_availability(self) -> tuple[bool, str | None, str | None]:
        """Detect pip-audit presence and parse version string."""
        try:
            res = subprocess.run(
                [sys.executable, "-m", "pip_audit", "--version"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if res.returncode == 0:
                output = (res.stdout or res.stderr).strip()
                # Parse e.g. "pip-audit 2.8.0"
                version = output.split()[-1] if output else "unknown"
                return True, version, None
            return False, None, f"pip-audit returned nonzero code: {res.returncode}"
        except FileNotFoundError:
            return False, None, "Python executable or pip-audit module not found."
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
        """Audit declared application requirements against PyPI/OSV vulnerability databases."""
        is_avail, version, reason = self.detect_availability()
        if not is_avail:
            raise ToolNotAvailableError(f"pip-audit scanner is unavailable: {reason}")

        opts = options or {}
        req_file = opts.get("requirements_file", "requirements.txt")
        req_path = Path(req_file).resolve()
        is_temp_audit = (
            "vadl_audit_" in str(req_path)
            or "tmp" in str(req_path).lower()
            or "temp" in str(req_path).lower()
        )
        if req_file not in ("requirements.txt", "requirements-dev.txt") and not is_temp_audit:
            raise ScannerError(
                "pip-audit is strictly restricted to 'requirements.txt' or 'requirements-dev.txt'."
            )
        if not req_path.name.endswith((".txt", ".in")):
            raise ScannerError(
                "pip-audit is strictly restricted to text requirements files (e.g. requirements.txt)."
            )
        if not req_path.exists():
            raise ScannerError(f"Target requirements file '{req_file}' does not exist on disk.")

        service = opts.get("service", "pypi")  # "pypi" or "osv"
        if service not in ("pypi", "osv"):
            service = "pypi"

        reports_dir = Path("reports/scans")
        reports_dir.mkdir(parents=True, exist_ok=True)
        report_file = reports_dir / f"{scan_uuid}_pip_audit.json"

        cmd = [
            sys.executable,
            "-m",
            "pip_audit",
            "-r",
            str(req_path),
            "-f",
            "json",
            "-s",
            service,
            "--progress-spinner",
            "off",
            "-o",
            str(report_file),
        ]

        logger.info(
            f"Executing pip-audit dependency scan against '{req_file}' (UUID: {scan_uuid})."
        )

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
                f"pip-audit execution exceeded timeout of {timeout_seconds}s."
            ) from exc
        except Exception as exc:
            raise ScannerExecutionError(f"Failed to execute pip-audit process: {exc}") from exc

        # pip-audit returns:
        # 0: Clean, no vulnerabilities
        # 1: Vulnerabilities found (normal audit result)
        # Any other exit code indicates network, dependency resolution, or execution error
        if proc.returncode not in (0, 1):
            err_msg = (
                proc.stderr.strip()
                or proc.stdout.strip()
                or f"pip-audit exited with code {proc.returncode}"
            )
            logger.error(f"pip-audit execution error: {err_msg}")
            raise ScannerExecutionError(
                f"Dependency audit failed (advisory service error or bad input): {err_msg}"
            )

        if not report_file.exists():
            raise ReportParsingError(
                "pip-audit did not generate the expected JSON output artifact."
            )

        try:
            with open(report_file, encoding="utf-8") as f:
                raw_json = json.load(f)
        except json.JSONDecodeError as exc:
            raise ReportParsingError(f"pip-audit output contains invalid JSON: {exc}") from exc

        raw_findings = self._parse_pip_audit_results(raw_json)

        return ScanExecutionResult(
            scanner_type=self.scanner_type,
            exit_code=proc.returncode,
            tool_version=version,
            tool_configuration={
                "requirements_file": req_file,
                "vulnerability_service": service,
                "timeout_seconds": timeout_seconds,
            },
            raw_report_path=str(report_file),
            findings=raw_findings,
            stdout=proc.stdout or "",
            stderr=proc.stderr or "",
        )

    def _parse_pip_audit_results(self, data: dict[str, Any]) -> list[RawFinding]:
        """Transform pip-audit JSON dependencies output into RawFinding structures."""
        deps = data.get("dependencies", [])
        findings: list[RawFinding] = []

        for dep in deps:
            pkg_name = dep.get("name", "unknown")
            installed_ver = dep.get("version", "unknown")
            vulns = dep.get("vulns", [])

            for vuln in vulns:
                vuln_id = vuln.get("id", "UNKNOWN_VULN")
                aliases = vuln.get("aliases", [])
                fix_versions = vuln.get("fix_versions", [])
                description = vuln.get(
                    "description", f"Vulnerability in {pkg_name} {installed_ver}"
                )

                alias_str = f" ({', '.join(aliases)})" if aliases else ""
                title = f"Vulnerable dependency {pkg_name}=={installed_ver}: {vuln_id}{alias_str}"

                remediation = (
                    f"Upgrade '{pkg_name}' to fixed version: {', '.join(fix_versions)}."
                    if fix_versions
                    else f"Review advisory {vuln_id} and isolate package '{pkg_name}' until a patch is released."
                )

                advisory_url = f"https://osv.dev/vulnerability/{vuln_id}"

                finding = RawFinding(
                    tool_finding_id=vuln_id,
                    title=title,
                    description=description,
                    raw_severity="HIGH",  # Known CVE in application dependency defaults to HIGH
                    raw_confidence="HIGH",  # Official database record match
                    category="Vulnerable and Outdated Components",
                    cwe_id="CWE-1395",  # Dependency on Vulnerable Third-Party Component
                    owasp_category="A06:2021-Vulnerable and Outdated Components",
                    target_component=f"{pkg_name}=={installed_ver}",
                    file_path="requirements.txt",
                    remediation_guidance=remediation,
                    advisory_url=advisory_url,
                    extra_metadata={
                        "package_name": pkg_name,
                        "installed_version": installed_ver,
                        "fixed_versions": fix_versions,
                        "aliases": aliases,
                    },
                )
                findings.append(finding)

        return findings
