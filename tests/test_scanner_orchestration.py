"""Automated tests for Phase 6 scanner orchestration, findings normalization, and deduplication."""

from unittest.mock import MagicMock, patch

import pytest

from app.engine.target_guard import AuthorizationError
from app.extensions import db
from app.models.lab import LabTarget
from app.models.scanner import NormalizedFinding, ScanAuditEvent
from app.models.user import Role, User
from app.scanner.adapters.base import RawFinding, ScanExecutionResult, ScannerError
from app.scanner.orchestrator import ScannerOrchestrator
from app.scanner.semantics import (
    FindingConfidence,
    FindingStatus,
    NormalizedSeverity,
    ScanAuditEventType,
    ScanLifecycle,
    ScannerType,
)


@pytest.fixture
def target_and_analyst(app, auth):
    """Fixture providing authorized lab target and analyst user."""
    with app.app_context():
        target = LabTarget.query.filter_by(base_url="http://127.0.0.1:5000/lab").first()
        if not target:
            target = LabTarget(
                name="Scanner Local Target",
                base_url="http://127.0.0.1:5000/lab",
                environment_id="testing",
                is_authorized=True,
            )
            db.session.add(target)
            db.session.commit()
        target_id = target.id

        analyst = auth.create_user(
            email="scanner_analyst@vadl.local",
            password="Password123!@",
            display_name="Scanner Analyst",
            role=Role.SECURITY_ANALYST,
        )
        analyst_id = analyst.id

    return target_id, analyst_id


def test_scanner_authorization_guards(app, auth):
    """Verify role-based authorization: ordinary users are forbidden from initiating scans."""
    with app.app_context():
        user = auth.create_user(
            email="ordinary_scanner_user@vadl.local",
            password="Password123!@",
            role=Role.USER,
        )
        with pytest.raises(AuthorizationError, match="Only security analysts and administrators"):
            ScannerOrchestrator.validate_scan_request(
                actor=user,
                scanner_type="bandit",
            )


def test_scanner_target_authorization_guard(app, auth):
    """Verify unauthorized or revoked lab targets are rejected."""
    with app.app_context():
        analyst = auth.create_user(
            email="target_guard_analyst@vadl.local",
            password="Password123!@",
            role=Role.SECURITY_ANALYST,
        )

        # 1. Unregistered target ID
        with pytest.raises(ScannerError):
            ScannerOrchestrator.validate_scan_request(
                actor=analyst,
                scanner_type="zap",
                target_id=999999,
            )

        # 2. Disabled/Revoked target
        disabled_target = LabTarget(
            name="Revoked Target",
            base_url="http://127.0.0.1:5000/lab",
            environment_id="testing",
            is_authorized=False,
        )
        db.session.add(disabled_target)
        db.session.commit()

        with pytest.raises(AuthorizationError, match="is not authorized for scanning"):
            ScannerOrchestrator.validate_scan_request(
                actor=analyst,
                scanner_type="zap",
                target_id=disabled_target.id,
            )


def test_scan_lifecycle_completed_with_findings(app, target_and_analyst):
    """Verify scan lifecycle transition to COMPLETED_WITH_FINDINGS and audit event persistence."""
    target_id, analyst_id = target_and_analyst

    with app.app_context():
        analyst = db.session.get(User, analyst_id)

        # Mock adapter execution returning findings
        mock_finding = RawFinding(
            tool_finding_id="B608",
            title="SQL Injection Vector",
            description="Hardcoded SQL expression detected",
            raw_severity="HIGH",
            raw_confidence="HIGH",
            target_component="app/routes/lab_vulnerable.py",
            file_path="app/routes/lab_vulnerable.py",
            line_number=54,
            evidence_snippet="SELECT * FROM products WHERE csrf_token=SECRET123",
            remediation_guidance="Use parameterized queries",
        )

        mock_exec_res = ScanExecutionResult(
            scanner_type=ScannerType.BANDIT,
            exit_code=1,
            tool_version="1.8.3",
            tool_configuration={"source_dir": "app"},
            raw_report_path="reports/scans/test_report.json",
            findings=[mock_finding],
        )

        with patch("app.scanner.orchestrator.get_scanner_adapter") as mock_get_adapter:
            mock_adapter = MagicMock()
            mock_adapter.execute_scan.return_value = mock_exec_res
            mock_get_adapter.return_value = mock_adapter

            scan = ScannerOrchestrator.run_scan(
                actor=analyst,
                scanner_type="bandit",
                source_dir="app",
            )

            assert scan.status == ScanLifecycle.COMPLETED_WITH_FINDINGS.value
            assert scan.total_findings == 1
            assert scan.high_count == 1
            assert scan.started_at is not None
            assert scan.completed_at is not None

            # Verify finding normalization & evidence sanitization
            findings = NormalizedFinding.query.filter_by(scan_id=scan.id).all()
            assert len(findings) == 1
            f = findings[0]
            assert f.severity == NormalizedSeverity.HIGH.value
            assert f.status == FindingStatus.NEW.value
            assert "[REDACTED_CSRF_TOKEN]" in f.evidence_snippet

            # Verify audit trail
            events = ScanAuditEvent.query.filter_by(scan_id=scan.id).all()
            event_types = [e.event_type for e in events]
            assert ScanAuditEventType.SCAN_REQUESTED.value in event_types
            assert ScanAuditEventType.SCAN_STARTED.value in event_types
            assert ScanAuditEventType.SCAN_COMPLETED.value in event_types


def test_findings_deduplication_and_history_preservation(app, target_and_analyst):
    """Verify deduplication updates status to ACTIVE while preserving first_seen_at and history."""
    target_id, analyst_id = target_and_analyst

    with app.app_context():
        analyst = db.session.get(User, analyst_id)

        finding_payload = RawFinding(
            tool_finding_id="PYSEC-2024-001",
            title="Vulnerable dependency package",
            description="Buffer overflow in parser",
            raw_severity="HIGH",
            target_component="libtest==1.0.0",
            remediation_guidance="Upgrade libtest",
        )

        mock_exec_res = ScanExecutionResult(
            scanner_type=ScannerType.PIP_AUDIT,
            exit_code=1,
            tool_version="2.8.0",
            tool_configuration={"requirements_file": "requirements.txt"},
            raw_report_path="reports/scans/audit1.json",
            findings=[finding_payload],
        )

        with patch("app.scanner.orchestrator.get_scanner_adapter") as mock_get_adapter:
            mock_adapter = MagicMock()
            mock_adapter.execute_scan.return_value = mock_exec_res
            mock_get_adapter.return_value = mock_adapter

            # Run Scan 1
            scan1 = ScannerOrchestrator.run_scan(actor=analyst, scanner_type="pip_audit")
            f1 = NormalizedFinding.query.filter_by(scan_id=scan1.id).first()
            assert f1.status == FindingStatus.NEW.value
            initial_first_seen = f1.first_seen_at
            fingerprint = f1.fingerprint

            # Run Scan 2 (repeats the same finding)
            scan2 = ScannerOrchestrator.run_scan(actor=analyst, scanner_type="pip_audit")
            f2 = NormalizedFinding.query.filter_by(scan_id=scan2.id).first()

            # Verify:
            # 1. Finding 1 from Scan 1 is preserved in DB (never overwritten or deleted)
            assert f1.id != f2.id
            assert f2.fingerprint == fingerprint

            # 2. Finding 2 correctly marked ACTIVE (already observed previously)
            assert f2.status == FindingStatus.ACTIVE.value

            # 3. First observed timestamp is preserved from Scan 1
            assert f2.first_seen_at == initial_first_seen


def test_severity_and_confidence_normalization_mappings():
    """Verify normalization mapping rules across diverse tool-specific taxonomies."""
    # Bandit severities
    assert ScannerOrchestrator._normalize_severity("HIGH") == NormalizedSeverity.HIGH
    assert ScannerOrchestrator._normalize_severity("MEDIUM") == NormalizedSeverity.MEDIUM
    assert ScannerOrchestrator._normalize_severity("LOW") == NormalizedSeverity.LOW
    assert ScannerOrchestrator._normalize_severity("UNDEFINED") == NormalizedSeverity.INFORMATIONAL

    # ZAP risk codes
    assert ScannerOrchestrator._normalize_severity("3") == NormalizedSeverity.HIGH
    assert ScannerOrchestrator._normalize_severity("2") == NormalizedSeverity.MEDIUM
    assert ScannerOrchestrator._normalize_severity("1") == NormalizedSeverity.LOW
    assert ScannerOrchestrator._normalize_severity("0") == NormalizedSeverity.INFORMATIONAL

    # Confidence mappings
    assert ScannerOrchestrator._normalize_confidence("HIGH") == FindingConfidence.HIGH
    assert ScannerOrchestrator._normalize_confidence("3") == FindingConfidence.HIGH
    assert ScannerOrchestrator._normalize_confidence("MEDIUM") == FindingConfidence.MEDIUM
    assert ScannerOrchestrator._normalize_confidence("LOW") == FindingConfidence.LOW
    assert ScannerOrchestrator._normalize_confidence(None) == FindingConfidence.UNKNOWN
