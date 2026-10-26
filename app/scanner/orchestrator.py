"""Automated security scanning orchestrator, findings normalizer, and deduplication engine (Phase 6)."""

import hashlib
import json
import logging
from datetime import UTC, datetime
from typing import Any

from app.engine.evidence import sanitize_text, truncate_evidence
from app.engine.target_guard import (
    AuthorizationError,
    recheck_target_authorization,
)
from app.extensions import db
from app.lab.target_validator import validate_lab_target_url
from app.models.lab import LabTarget
from app.models.scanner import NormalizedFinding, ScanAuditEvent, SecurityScan
from app.models.user import Role, User
from app.scanner.adapters.base import (
    ScanExecutionResult,
    ScannerError,
    ScannerExecutionError,
    ScannerTimeoutError,
    ToolNotAvailableError,
)
from app.scanner.adapters.registry import get_scanner_adapter
from app.scanner.grader import grade_posture
from app.scanner.semantics import (
    FindingConfidence,
    FindingStatus,
    NormalizedSeverity,
    ScanAuditEventType,
    ScanLifecycle,
    ScannerType,
)

logger = logging.getLogger("vadl.scanner.orchestrator")


class ScannerOrchestrator:
    """Orchestrates security scanner executions, normalizes findings, and records audit logs."""

    @classmethod
    def validate_scan_request(
        cls,
        *,
        actor: User,
        scanner_type: str,
        target_id: int | None = None,
        source_dir: str | None = None,
        profile: str = "baseline",
    ) -> tuple[ScannerType, LabTarget | None]:
        """Verify actor permissions, scanner allowlist, and target authorization boundaries."""
        if not actor or not actor.has_role(Role.SECURITY_ANALYST, Role.ADMIN):
            raise AuthorizationError(
                "Only security analysts and administrators may initiate security scans."
            )

        try:
            resolved_scanner = ScannerType(scanner_type)
        except ValueError:
            raise ScannerError(
                f"Scanner '{scanner_type}' is not recognized in the approved scanner allowlist."
            ) from None

        lab_target = None
        if resolved_scanner == ScannerType.ZAP:
            if not target_id:
                # Default to first authorized local lab target
                lab_target = LabTarget.query.filter_by(is_authorized=True).first()
                if not lab_target:
                    raise AuthorizationError(
                        "No authorized laboratory targets are currently available for DAST scanning."
                    )
            else:
                lab_target = db.session.get(LabTarget, target_id)
                if not lab_target:
                    raise ScannerError(f"Target #{target_id} does not exist.")
                if not lab_target.is_authorized:
                    raise AuthorizationError(
                        f"Target '{lab_target.name}' is not authorized for scanning."
                    )

            # Validate target host against security allowlist
            allowed, reason = validate_lab_target_url(lab_target.base_url)
            if not allowed:
                raise AuthorizationError(
                    f"Target URL '{lab_target.base_url}' is not permitted: {reason}"
                )

        return resolved_scanner, lab_target

    @classmethod
    def run_scan(
        cls,
        *,
        actor: User,
        scanner_type: str,
        target_id: int | None = None,
        target_edition: str | None = None,
        source_dir: str | None = None,
        profile: str = "baseline",
        timeout_seconds: int = 120,
        options: dict[str, Any] | None = None,
    ) -> SecurityScan:
        """Execute a validated security scan synchronously, normalize findings, and persist results."""
        resolved_type, lab_target = cls.validate_scan_request(
            actor=actor,
            scanner_type=scanner_type,
            target_id=target_id,
            source_dir=source_dir,
            profile=profile,
        )

        now = datetime.now(UTC)
        scan = SecurityScan(
            scanner_type=resolved_type.value,
            scan_profile=profile,
            status=ScanLifecycle.QUEUED.value,
            target_id=lab_target.id if lab_target else None,
            target_edition=target_edition,
            source_path=source_dir if resolved_type == ScannerType.BANDIT else None,
            initiated_by_user_id=actor.id,
            created_at=now,
        )
        db.session.add(scan)
        db.session.flush()

        cls._record_audit_event(
            scan_id=scan.id,
            event_type=ScanAuditEventType.SCAN_REQUESTED.value,
            actor_id=actor.id,
            details=f"Scan #{scan.id} ({resolved_type.value}, profile: {profile}) requested by {actor.email}.",
        )
        db.session.commit()

        # Begin Execution
        scan.status = ScanLifecycle.RUNNING.value
        scan.started_at = datetime.now(UTC)
        cls._record_audit_event(
            scan_id=scan.id,
            event_type=ScanAuditEventType.SCAN_STARTED.value,
            actor_id=actor.id,
            details=f"Scan #{scan.id} execution started.",
        )
        db.session.commit()

        adapter = get_scanner_adapter(resolved_type)

        try:
            # Immediate pre-execution re-check for ZAP targets
            target_url = None
            if resolved_type == ScannerType.ZAP and lab_target:
                is_auth, auth_msg = recheck_target_authorization(lab_target.id)
                if not is_auth:
                    raise AuthorizationError(
                        f"Target authorization revoked prior to scan execution: {auth_msg}"
                    )
                # Build target URL incorporating target edition if specified
                target_url = lab_target.base_url
                if target_edition == "vulnerable" and not target_url.endswith("/vulnerable"):
                    target_url = f"{target_url.rstrip('/')}/vulnerable"
                elif target_edition == "secure" and not target_url.endswith("/secure"):
                    target_url = f"{target_url.rstrip('/')}/secure"

            # Execute the scanner adapter
            exec_result: ScanExecutionResult = adapter.execute_scan(
                scan_uuid=scan.uuid,
                target_url=target_url,
                source_dir=source_dir,
                profile=profile,
                timeout_seconds=timeout_seconds,
                options=options,
            )

            # Process and normalize findings
            cls._process_and_save_findings(scan, exec_result)

            # Determine final scan lifecycle state:
            # A completed scan with vulnerabilities is still successfully executed.
            if scan.total_findings > 0:
                scan.status = ScanLifecycle.COMPLETED_WITH_FINDINGS.value
            else:
                scan.status = ScanLifecycle.COMPLETED.value

            scan.completed_at = datetime.now(UTC)
            scan.tool_version = exec_result.tool_version
            scan.tool_configuration = json.dumps(exec_result.tool_configuration)
            scan.raw_report_path = exec_result.raw_report_path

            cls._record_audit_event(
                scan_id=scan.id,
                event_type=ScanAuditEventType.SCAN_COMPLETED.value,
                actor_id=actor.id,
                details=(
                    f"Scan #{scan.id} finished with status '{scan.status}'. "
                    f"Findings: {scan.total_findings} (Critical: {scan.critical_count}, "
                    f"High: {scan.high_count}, Medium: {scan.medium_count}, Low: {scan.low_count})."
                ),
            )
            db.session.commit()
            return scan

        except ScannerTimeoutError as exc:
            scan.status = ScanLifecycle.TIMED_OUT.value
            scan.completed_at = datetime.now(UTC)
            scan.error_message = str(exc)
            cls._record_audit_event(
                scan_id=scan.id,
                event_type=ScanAuditEventType.SCAN_TIMED_OUT.value,
                actor_id=actor.id,
                details=f"Scan #{scan.id} timed out: {exc}",
            )
            db.session.commit()
            logger.warning(f"Scan #{scan.id} timed out: {exc}")
            return scan

        except (
            AuthorizationError,
            ToolNotAvailableError,
            ScannerExecutionError,
            ScannerError,
        ) as exc:
            scan.status = ScanLifecycle.FAILED.value
            scan.completed_at = datetime.now(UTC)
            scan.error_message = str(exc)
            cls._record_audit_event(
                scan_id=scan.id,
                event_type=ScanAuditEventType.SCAN_FAILED.value,
                actor_id=actor.id,
                details=f"Scan #{scan.id} failed: {exc}",
            )
            db.session.commit()
            logger.error(f"Scan #{scan.id} failed: {exc}")
            return scan

        except Exception as exc:
            scan.status = ScanLifecycle.FAILED.value
            scan.completed_at = datetime.now(UTC)
            scan.error_message = f"Unhandled scan execution failure: {exc}"
            cls._record_audit_event(
                scan_id=scan.id,
                event_type=ScanAuditEventType.SCAN_FAILED.value,
                actor_id=actor.id,
                details=f"Scan #{scan.id} crashed with unhandled exception: {exc}",
            )
            db.session.commit()
            logger.exception(f"Unexpected exception in Scan #{scan.id}: {exc}")
            return scan

    @classmethod
    def _process_and_save_findings(cls, scan: SecurityScan, result: ScanExecutionResult) -> None:
        """Normalize, deduplicate, and persist security findings."""
        now = datetime.now(UTC)
        critical_c = 0
        high_c = 0
        med_c = 0
        low_c = 0
        info_c = 0

        for raw in result.findings:
            # 1. Map severity to common normalized enum
            norm_severity = cls._normalize_severity(raw.raw_severity)
            if norm_severity == NormalizedSeverity.CRITICAL:
                critical_c += 1
            elif norm_severity == NormalizedSeverity.HIGH:
                high_c += 1
            elif norm_severity == NormalizedSeverity.MEDIUM:
                med_c += 1
            elif norm_severity == NormalizedSeverity.LOW:
                low_c += 1
            else:
                info_c += 1

            # 2. Map confidence
            norm_confidence = cls._normalize_confidence(raw.raw_confidence)

            # 3. Compute stable deduplication fingerprint
            fingerprint = cls.compute_fingerprint(
                scanner_name=result.scanner_type.value,
                tool_finding_id=raw.tool_finding_id,
                target_component=raw.target_component,
                file_path=raw.file_path,
                line_number=raw.line_number,
            )

            # 4. Check historical finding status
            prior_finding = (
                NormalizedFinding.query.filter_by(fingerprint=fingerprint)
                .order_by(NormalizedFinding.first_seen_at.asc())
                .first()
            )

            if prior_finding:
                first_seen = prior_finding.first_seen_at
                status = FindingStatus.ACTIVE.value
            else:
                first_seen = now
                status = FindingStatus.NEW.value

            # Sanitize and bound evidence snippet
            sanitized_evidence = sanitize_text(raw.evidence_snippet)
            bounded_evidence = truncate_evidence(sanitized_evidence, max_bytes=2048)

            finding = NormalizedFinding(
                scan_id=scan.id,
                scanner_name=result.scanner_type.value,
                tool_finding_id=raw.tool_finding_id,
                title=raw.title,
                description=raw.description,
                category=raw.category,
                cwe_id=raw.cwe_id,
                owasp_category=raw.owasp_category,
                severity=norm_severity.value,
                original_severity=raw.raw_severity,
                confidence=norm_confidence.value,
                original_confidence=raw.raw_confidence,
                target_component=raw.target_component,
                file_path=raw.file_path,
                line_number=raw.line_number,
                evidence_snippet=bounded_evidence,
                remediation_guidance=raw.remediation_guidance,
                advisory_url=raw.advisory_url,
                fingerprint=fingerprint,
                status=status,
                is_lab_scenario=raw.extra_metadata.get("is_lab_scenario", False),
                scenario_id=raw.extra_metadata.get("scenario_id"),
                first_seen_at=first_seen,
                last_seen_at=now,
                created_at=now,
            )
            db.session.add(finding)

        scan.total_findings = len(result.findings)
        scan.critical_count = critical_c
        scan.high_count = high_c
        scan.medium_count = med_c
        scan.low_count = low_c
        scan.info_count = info_c

        # Grade security posture
        findings_summary = [
            {
                "title": r.title,
                "category": r.category or "General Security",
                "severity": cls._normalize_severity(r.raw_severity).value,
                "remediation_guidance": r.remediation_guidance,
            }
            for r in result.findings
        ]
        grade_res = grade_posture(findings_summary, mode=scan.scanner_type)
        scan.score = grade_res["score"]
        scan.grade = grade_res["grade"]
        scan.grade_breakdown = json.dumps(grade_res)

    @classmethod
    def compute_fingerprint(
        cls,
        *,
        scanner_name: str,
        tool_finding_id: str,
        target_component: str,
        file_path: str | None = None,
        line_number: int | None = None,
    ) -> str:
        """Compute stable SHA-256 fingerprint for finding deduplication across scans."""
        key_parts = [
            scanner_name.strip().lower(),
            tool_finding_id.strip(),
            (target_component or "").strip().lower(),
            (file_path or "").strip().lower(),
            str(line_number or ""),
        ]
        composite_key = ":".join(key_parts)
        return hashlib.sha256(composite_key.encode("utf-8")).hexdigest()

    @staticmethod
    def _normalize_severity(raw_severity: str | None) -> NormalizedSeverity:
        """Documented mapping of tool-specific severities to common NormalizedSeverity."""
        if not raw_severity:
            return NormalizedSeverity.INFORMATIONAL
        s = raw_severity.strip().upper()
        if s in ("CRITICAL", "BLOCKER"):
            return NormalizedSeverity.CRITICAL
        if s in ("HIGH", "MAJOR", "3"):
            return NormalizedSeverity.HIGH
        if s in ("MEDIUM", "MODERATE", "WARN", "WARNING", "2"):
            return NormalizedSeverity.MEDIUM
        if s in ("LOW", "MINOR", "1"):
            return NormalizedSeverity.LOW
        return NormalizedSeverity.INFORMATIONAL

    @staticmethod
    def _normalize_confidence(raw_confidence: str | None) -> FindingConfidence:
        """Documented mapping of tool-specific confidence levels to FindingConfidence."""
        if not raw_confidence:
            return FindingConfidence.UNKNOWN
        c = raw_confidence.strip().upper()
        if c in ("HIGH", "3"):
            return FindingConfidence.HIGH
        if c in ("MEDIUM", "2"):
            return FindingConfidence.MEDIUM
        if c in ("LOW", "1"):
            return FindingConfidence.LOW
        return FindingConfidence.UNKNOWN

    @staticmethod
    def _record_audit_event(scan_id: int, event_type: str, actor_id: int, details: str) -> None:
        """Persist structured scan audit event."""
        event = ScanAuditEvent(
            scan_id=scan_id,
            event_type=event_type,
            actor_id=actor_id,
            details=details,
            timestamp=datetime.now(UTC),
        )
        db.session.add(event)
