"""OWASP ZAP dynamic application security testing (DAST) adapter (Phase 6)."""

import json
import logging
import shutil
import subprocess
from pathlib import Path
from typing import Any

from app.engine.evidence import sanitize_text, truncate_evidence
from app.lab.target_validator import validate_lab_target_url
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

logger = logging.getLogger("vadl.scanner.zap")

# Documented and pinned ZAP official Docker image tag
PINNED_ZAP_IMAGE = "ghcr.io/zaproxy/zaproxy:2.15.0"
ZAP_DOCKER_NETWORK = "vadl-isolated-network"


class ZapAdapter(BaseScannerAdapter):
    """Adapter for executing OWASP ZAP baseline passive or active scans against local lab targets."""

    scanner_type = ScannerType.ZAP

    def detect_availability(self) -> tuple[bool, str | None, str | None]:
        """Detect Docker engine and OWASP ZAP image availability."""
        # Check if docker binary exists
        docker_bin = shutil.which("docker")
        if not docker_bin:
            return False, None, "Docker CLI executable not found on system PATH."

        # Check if docker daemon is running and responsive
        try:
            res = subprocess.run(
                ["docker", "info", "--format", "{{.ServerVersion}}"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if res.returncode != 0:
                return (
                    False,
                    None,
                    "Docker daemon is not running or current user lacks access permissions.",
                )
            server_version = res.stdout.strip()
            return True, f"Docker {server_version} ({PINNED_ZAP_IMAGE})", None
        except Exception as exc:
            return False, None, f"Docker daemon probe failed: {exc}"

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
        """Execute OWASP ZAP baseline passive scan against an authorized lab target."""
        opts = options or {}

        # 1. Target Validation & Safety Guards
        if not target_url:
            raise ScannerError("OWASP ZAP scan requires an authorized target URL.")

        # Validate URL conforms strictly to internal laboratory host allowlist
        allowed, reason = validate_lab_target_url(target_url)
        if not allowed:
            raise ScannerError(f"Target URL rejected by security allowlist: {reason}")

        # Active scan safety gate
        is_active_profile = profile == "active"
        if is_active_profile:
            allow_active = opts.get("allow_active_scan", False)
            if not allow_active:
                raise ScannerError(
                    "Active scanning is disabled by default. An explicit confirmation flag is required."
                )
            if (
                "localhost" not in target_url
                and "127.0.0.1" not in target_url
                and "vadl-" not in target_url
            ):
                raise ScannerError(
                    "Active scanning is strictly prohibited against non-local targets."
                )

        # 2. Check Mock / Fixture Mode (for reproducible CI and environments without Docker)
        mock_report_path = opts.get("mock_report_path")
        if mock_report_path:
            return self._execute_mock_scan(
                scan_uuid=scan_uuid,
                mock_report_path=mock_report_path,
                target_url=target_url,
                profile=profile,
            )

        # 3. Tool Availability Check
        is_avail, tool_version, reason = self.detect_availability()
        if not is_avail:
            raise ToolNotAvailableError(
                f"OWASP ZAP scanner is unavailable: {reason}. "
                "Ensure Docker is running and attached to the 'vadl-isolated-network'."
            )

        # 4. Prepare Bounded Report Directory and Artifact Names
        reports_dir = Path("reports/scans").resolve()
        reports_dir.mkdir(parents=True, exist_ok=True)
        report_filename = f"{scan_uuid}_zap.json"
        report_file_host = reports_dir / report_filename

        # Maximum duration in minutes for ZAP baseline scan
        max_duration_mins = max(1, min(10, timeout_seconds // 60))

        # Select scan script based on profile
        script_name = "zap-full-scan.py" if is_active_profile else "zap-baseline.py"

        # Build Docker command ensuring strict isolation:
        # - Attaches to vadl-isolated-network
        # - Mounts only the reports working directory
        # - Never mounts /var/run/docker.sock
        # - Applies container memory limit
        cmd = [
            "docker",
            "run",
            "--rm",
            "--network",
            ZAP_DOCKER_NETWORK,
            "-m",
            "1024m",
            "-v",
            f"{reports_dir}:/zap/wrk:rw",
            "-t",
            PINNED_ZAP_IMAGE,
            script_name,
            "-t",
            target_url,
            "-J",
            report_filename,
            "-m",
            str(max_duration_mins),
        ]

        logger.info(f"Executing ZAP DAST ({profile}) against '{target_url}' (UUID: {scan_uuid}).")

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
                f"OWASP ZAP scan exceeded timeout of {timeout_seconds}s."
            ) from exc
        except Exception as exc:
            raise ScannerExecutionError(f"Failed to execute OWASP ZAP container: {exc}") from exc

        # ZAP baseline scan exit codes:
        # 0: Success, no warnings/errors
        # 1: Success, at least one WARN found
        # 2: Success, at least one FAIL found
        # 3: Scanner error or bad arguments
        if proc.returncode > 2:
            err_msg = (
                proc.stderr.strip()
                or proc.stdout.strip()
                or f"ZAP exited with error code {proc.returncode}"
            )
            logger.error(f"ZAP container execution error: {err_msg}")
            raise ScannerExecutionError(f"OWASP ZAP container error: {err_msg}")

        if not report_file_host.exists():
            raise ReportParsingError(
                "OWASP ZAP did not generate the expected JSON report artifact."
            )

        try:
            with open(report_file_host, encoding="utf-8") as f:
                raw_json = json.load(f)
        except json.JSONDecodeError as exc:
            raise ReportParsingError(f"OWASP ZAP report contains invalid JSON: {exc}") from exc

        raw_findings = self._parse_zap_results(raw_json)

        return ScanExecutionResult(
            scanner_type=self.scanner_type,
            exit_code=proc.returncode,
            tool_version=PINNED_ZAP_IMAGE,
            tool_configuration={
                "target_url": target_url,
                "profile": profile,
                "docker_image": PINNED_ZAP_IMAGE,
                "network": ZAP_DOCKER_NETWORK,
                "timeout_seconds": timeout_seconds,
            },
            raw_report_path=str(report_file_host),
            findings=raw_findings,
            stdout=proc.stdout or "",
            stderr=proc.stderr or "",
        )

    def _execute_mock_scan(
        self,
        *,
        scan_uuid: str,
        mock_report_path: str,
        target_url: str,
        profile: str,
    ) -> ScanExecutionResult:
        """Load deterministic fixture report for unit and integration testing environments."""
        path = Path(mock_report_path)
        if not path.exists():
            raise ScannerError(f"Mock report fixture '{mock_report_path}' not found.")

        try:
            with open(path, encoding="utf-8") as f:
                raw_json = json.load(f)
        except json.JSONDecodeError as exc:
            raise ReportParsingError(f"Mock report fixture contains invalid JSON: {exc}") from exc

        reports_dir = Path("reports/scans")
        reports_dir.mkdir(parents=True, exist_ok=True)
        report_file_host = reports_dir / f"{scan_uuid}_zap.json"
        with open(report_file_host, "w", encoding="utf-8") as f:
            json.dump(raw_json, f, indent=2)

        raw_findings = self._parse_zap_results(raw_json)

        return ScanExecutionResult(
            scanner_type=self.scanner_type,
            exit_code=1 if raw_findings else 0,
            tool_version="OWASP ZAP 2.15.0 (Mock/Fixture)",
            tool_configuration={
                "target_url": target_url,
                "profile": profile,
                "mock_fixture": str(path),
            },
            raw_report_path=str(report_file_host),
            findings=raw_findings,
            stdout="ZAP baseline scan completed against local mock target.",
            stderr="",
        )

    def _parse_zap_results(self, data: dict[str, Any]) -> list[RawFinding]:
        """Transform OWASP ZAP alerts into normalized RawFinding structures."""
        sites = data.get("site", [])
        findings: list[RawFinding] = []

        for site in sites:
            alerts = site.get("alerts", [])
            for alert in alerts:
                plugin_id = str(alert.get("pluginid", "0"))
                name = alert.get("name") or alert.get("alert") or "Unknown ZAP Alert"
                risk_code = str(alert.get("riskcode", "0"))
                confidence_code = str(alert.get("confidence", "1"))
                desc = alert.get("desc", "")
                solution = alert.get("solution", "")
                cwe_id = (
                    f"CWE-{alert.get('cweid')}"
                    if alert.get("cweid") and alert.get("cweid") != "-1"
                    else None
                )
                wasc_id = alert.get("wascid")
                advisory_url = alert.get("reference")

                # Map ZAP riskcode:
                # 3: High, 2: Medium, 1: Low, 0: Informational
                raw_severity = {
                    "3": "HIGH",
                    "2": "MEDIUM",
                    "1": "LOW",
                    "0": "INFORMATIONAL",
                }.get(risk_code, "LOW")

                # Map ZAP confidence:
                # 3: High, 2: Medium, 1: Low, 0: False Positive
                raw_confidence = {
                    "3": "HIGH",
                    "2": "MEDIUM",
                    "1": "LOW",
                    "0": "UNKNOWN",
                }.get(confidence_code, "MEDIUM")

                # Extract first instance evidence
                instances = alert.get("instances", [])
                target_component = site.get("@name", "")
                evidence_text = ""
                if instances:
                    first_inst = instances[0]
                    target_component = first_inst.get("uri", target_component)
                    evidence_text = first_inst.get("evidence", "")

                sanitized_evidence = sanitize_text(evidence_text)
                bounded_evidence = truncate_evidence(sanitized_evidence, max_bytes=2048)

                # Link scenario if matching known VADL scenario
                scenario_id = self._match_scenario_id(plugin_id, name, target_component)
                is_lab = "/lab/vulnerable" in target_component or "vulnerable" in target_component

                finding = RawFinding(
                    tool_finding_id=f"ZAP-{plugin_id}",
                    title=f"OWASP ZAP: {name}",
                    description=desc,
                    raw_severity=raw_severity,
                    raw_confidence=raw_confidence,
                    category=alert.get("alertRef", "DAST Alert"),
                    cwe_id=cwe_id,
                    owasp_category=self._derive_owasp(plugin_id, name, cwe_id),
                    target_component=target_component,
                    evidence_snippet=bounded_evidence,
                    remediation_guidance=solution,
                    advisory_url=advisory_url,
                    extra_metadata={
                        "plugin_id": plugin_id,
                        "wasc_id": wasc_id,
                        "instance_count": alert.get("count", "1"),
                        "is_lab_scenario": is_lab,
                        "scenario_id": scenario_id,
                    },
                )
                findings.append(finding)

        return findings

    @staticmethod
    def _match_scenario_id(plugin_id: str, name: str, uri: str) -> str | None:
        """Correlate ZAP alert to known VADL scenario if applicable."""
        name_lower = name.lower()
        if "sql injection" in name_lower or "40018" in plugin_id:
            return "VADL-SQLI-001"
        if "cross site scripting" in name_lower or "xss" in name_lower or "40012" in plugin_id:
            return "VADL-XSS-001"
        if (
            "anti-clickjacking" in name_lower
            or "x-frame-options" in name_lower
            or "10020" in plugin_id
        ):
            return "VADL-HEADERS-001"
        if "content-security-policy" in name_lower or "10038" in plugin_id:
            return "VADL-HEADERS-001"
        if "x-content-type-options" in name_lower or "10021" in plugin_id:
            return "VADL-HEADERS-001"
        return None

    @staticmethod
    def _derive_owasp(plugin_id: str, name: str, cwe_id: str | None) -> str:
        """Map ZAP alert to OWASP Top 10 category."""
        name_lower = name.lower()
        if "sql" in name_lower or cwe_id == "CWE-89":
            return "A03:2021-Injection"
        if "xss" in name_lower or cwe_id == "CWE-79":
            return "A03:2021-Injection"
        if "header" in name_lower or "options" in name_lower or cwe_id == "CWE-16":
            return "A05:2021-Security Misconfiguration"
        if "cors" in name_lower or "cookie" in name_lower:
            return "A01:2021-Broken Access Control"
        return "A05:2021-Security Misconfiguration"
