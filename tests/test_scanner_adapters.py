"""Automated tests for Phase 6 scanner adapters (Bandit, pip-audit, OWASP ZAP)."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from app.scanner.adapters.bandit_adapter import BanditAdapter
from app.scanner.adapters.base import (
    ReportParsingError,
    ScannerError,
    ScannerExecutionError,
)
from app.scanner.adapters.pip_audit_adapter import PipAuditAdapter
from app.scanner.adapters.registry import get_all_scanners, get_scanner_adapter
from app.scanner.adapters.zap_adapter import ZapAdapter
from app.scanner.semantics import ScannerType

# ==============================================================================
# Bandit Adapter Unit Tests
# ==============================================================================


def test_bandit_adapter_version_detection():
    """Verify Bandit adapter detects tool presence and version string."""
    adapter = BanditAdapter()
    is_avail, version, reason = adapter.detect_availability()
    assert is_avail is True
    assert version is not None
    assert reason is None
    assert "." in version  # Semantic version e.g. "1.8.3"


def test_bandit_adapter_restricts_source_directory():
    """Verify Bandit adapter rejects directories outside the 'app' tree."""
    adapter = BanditAdapter()
    with pytest.raises(ScannerError, match="restricted to the 'app' source directory"):
        adapter.execute_scan(scan_uuid="test-uuid", source_dir="/etc/passwd")


def test_bandit_adapter_executes_live_scan():
    """Verify Bandit adapter runs against 'app' and outputs valid ScanExecutionResult."""
    adapter = BanditAdapter()
    res = adapter.execute_scan(scan_uuid="bandit-test-live", source_dir="app")
    assert res.scanner_type == ScannerType.BANDIT
    assert res.exit_code in (0, 1)
    assert res.raw_report_path is not None
    assert Path(res.raw_report_path).exists()
    assert isinstance(res.findings, list)


def test_bandit_adapter_parses_findings_and_annotates_lab_flaws():
    """Verify Bandit parser correctly extracts CWE, line numbers, and lab flaw annotations."""
    adapter = BanditAdapter()
    sample_bandit_json = {
        "results": [
            {
                "test_id": "B608",
                "test_name": "hardcoded_sql_expressions",
                "issue_severity": "HIGH",
                "issue_confidence": "MEDIUM",
                "issue_text": "Possible SQL injection vector through string-based query construction.",
                "filename": "app/routes/lab_vulnerable.py",
                "line_number": 45,
                "code": "query = f'SELECT * FROM products WHERE category = \"{cat}\"'",
                "issue_cwe": {"id": 89, "link": "https://cwe.mitre.org/data/definitions/89.html"},
                "more_info": "https://bandit.readthedocs.io/en/latest/plugins/b608_hardcoded_sql_expressions.html",
            }
        ]
    }
    findings = adapter._parse_bandit_results(sample_bandit_json)
    assert len(findings) == 1
    f = findings[0]
    assert f.tool_finding_id == "B608"
    assert f.raw_severity == "HIGH"
    assert f.raw_confidence == "MEDIUM"
    assert f.cwe_id == "CWE-89"
    assert f.file_path == "app/routes/lab_vulnerable.py"
    assert f.line_number == 45
    assert f.extra_metadata["is_lab_scenario"] is True
    assert f.extra_metadata["scenario_id"] == "VADL-SQLI-001"
    assert "intentional security vulnerability" in f.remediation_guidance


def test_bandit_adapter_handles_unparseable_json(tmp_path):
    """Verify Bandit adapter raises ReportParsingError when output JSON is malformed."""
    adapter = BanditAdapter()
    bad_report = tmp_path / "bad_bandit.json"
    bad_report.write_text("NOT_VALID_JSON", encoding="utf-8")

    with (
        patch("subprocess.run") as mock_run,
        patch.object(Path, "exists", return_value=True),
        patch("builtins.open", side_effect=json.JSONDecodeError("msg", "doc", 0)),
        pytest.raises(ReportParsingError),
    ):
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        adapter.execute_scan(scan_uuid="bad-json-uuid", source_dir="app")


# ==============================================================================
# pip-audit Adapter Unit Tests
# ==============================================================================


def test_pip_audit_adapter_version_detection():
    """Verify pip-audit adapter detects tool presence and version string."""
    adapter = PipAuditAdapter()
    is_avail, version, reason = adapter.detect_availability()
    assert is_avail is True
    assert version is not None
    assert reason is None
    assert "." in version  # Semantic version e.g. "2.8.0"


def test_pip_audit_adapter_restricts_requirements_file():
    """Verify pip-audit rejects arbitrary user-supplied requirement paths."""
    adapter = PipAuditAdapter()
    with pytest.raises(ScannerError, match="restricted to 'requirements.txt'"):
        adapter.execute_scan(
            scan_uuid="test-uuid",
            options={"requirements_file": "malicious_packages.txt"},
        )


def test_pip_audit_adapter_parses_findings():
    """Verify pip-audit parser extracts packages, CVEs, and remediation advice."""
    adapter = PipAuditAdapter()
    sample_audit_json = {
        "dependencies": [
            {
                "name": "insecure-pkg",
                "version": "0.9.0",
                "vulns": [
                    {
                        "id": "PYSEC-2024-9999",
                        "aliases": ["CVE-2024-9999"],
                        "fix_versions": ["1.0.0"],
                        "description": "Remote code execution in deserialization handler.",
                    }
                ],
            }
        ]
    }
    findings = adapter._parse_pip_audit_results(sample_audit_json)
    assert len(findings) == 1
    f = findings[0]
    assert f.tool_finding_id == "PYSEC-2024-9999"
    assert "insecure-pkg==0.9.0" in f.target_component
    assert f.cwe_id == "CWE-1395"
    assert "Upgrade 'insecure-pkg' to fixed version: 1.0.0" in f.remediation_guidance


def test_pip_audit_adapter_handles_advisory_failure():
    """Verify pip-audit handles execution and network advisory errors cleanly."""
    adapter = PipAuditAdapter()
    with (
        patch.object(adapter, "detect_availability", return_value=(True, "2.8.0", None)),
        patch("subprocess.run") as mock_run,
        pytest.raises(ScannerExecutionError, match="Dependency audit failed"),
    ):
        mock_run.return_value = MagicMock(returncode=2, stdout="", stderr="Connection timed out")
        adapter.execute_scan(scan_uuid="err-uuid")


# ==============================================================================
# OWASP ZAP Adapter Unit Tests
# ==============================================================================


def test_zap_adapter_missing_docker_handling():
    """Verify ZAP adapter detects missing Docker daemon and provides clear diagnostic message."""
    adapter = ZapAdapter()
    with patch("shutil.which", return_value=None):
        is_avail, version, reason = adapter.detect_availability()
        assert is_avail is False
        assert version is None
        assert "Docker CLI executable not found" in reason


def test_zap_adapter_rejects_unallowed_target_urls():
    """Verify ZAP adapter rejects public domains, metadata addresses, and arbitrary external URLs."""
    adapter = ZapAdapter()

    # Public external domain
    with pytest.raises(ScannerError, match="rejected by security allowlist"):
        adapter.execute_scan(scan_uuid="test-uuid", target_url="https://google.com")

    # Cloud metadata endpoint
    with pytest.raises(ScannerError, match="rejected by security allowlist"):
        adapter.execute_scan(
            scan_uuid="test-uuid", target_url="http://169.254.169.254/latest/meta-data"
        )


def test_zap_adapter_active_profile_requires_confirmation_flag():
    """Verify ZAP active scanning requires explicit confirmation flag."""
    adapter = ZapAdapter()
    with pytest.raises(ScannerError, match="Active scanning is disabled by default"):
        adapter.execute_scan(
            scan_uuid="test-uuid",
            target_url="http://127.0.0.1:5000/lab",
            profile="active",
            options={"allow_active_scan": False},
        )


def test_zap_adapter_parses_sample_fixture_report():
    """Verify ZAP adapter parses ZAP JSON alert format and maps risks to normalized severities."""
    adapter = ZapAdapter()
    fixture_path = "tests/fixtures/zap_report_sample.json"
    assert Path(fixture_path).exists()

    res = adapter.execute_scan(
        scan_uuid="fixture-zap-test",
        target_url="http://127.0.0.1:5000/lab",
        profile="baseline",
        options={"mock_report_path": fixture_path},
    )

    assert res.scanner_type == ScannerType.ZAP
    assert len(res.findings) == 3

    # Check finding 1: X-Frame-Options
    f1 = next(f for f in res.findings if "Anti-clickjacking" in f.title)
    assert f1.raw_severity == "MEDIUM"
    assert f1.cwe_id == "CWE-16"
    assert f1.extra_metadata["scenario_id"] == "VADL-HEADERS-001"

    # Check finding 3: SQL Injection
    f3 = next(f for f in res.findings if "SQL Injection" in f.title)
    assert f3.raw_severity == "HIGH"
    assert f3.cwe_id == "CWE-89"
    assert f3.extra_metadata["scenario_id"] == "VADL-SQLI-001"


# ==============================================================================
# Registry Tests
# ==============================================================================


def test_scanner_registry_contains_all_three_scanners():
    """Verify registry resolves adapters for bandit, pip_audit, and zap."""
    scanners = get_all_scanners()
    types = {s["scanner_type"] for s in scanners}
    assert types == {"bandit", "pip_audit", "zap"}

    for s_type in ScannerType:
        adapter = get_scanner_adapter(s_type)
        assert adapter.scanner_type == s_type


def test_scanner_registry_rejects_unregistered_type():
    """Verify registry raises ValueError on unknown scanner type."""
    with pytest.raises(ValueError, match="not in the approved scanner allowlist"):
        get_scanner_adapter("arbitrary_unknown_scanner")
