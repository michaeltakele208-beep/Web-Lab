"""Standardized vocabulary and semantics for automated security scanning (Phase 6)."""

from enum import Enum


class ScannerType(str, Enum):
    """Allowlist of supported automated security scanner tools."""

    ZAP = "zap"
    BANDIT = "bandit"
    PIP_AUDIT = "pip_audit"


class ScanLifecycle(str, Enum):
    """Explicit lifecycle states for automated security scans."""

    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    COMPLETED_WITH_FINDINGS = "COMPLETED_WITH_FINDINGS"
    FAILED = "FAILED"
    TIMED_OUT = "TIMED_OUT"
    CANCELLED = "CANCELLED"


class NormalizedSeverity(str, Enum):
    """Common normalized severity classification across all security scanning tools."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class FindingConfidence(str, Enum):
    """Confidence levels indicating the likelihood that a finding represents a true vulnerability."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class FindingStatus(str, Enum):
    """Tracking lifecycle status for normalized security findings."""

    NEW = "NEW"
    ACTIVE = "ACTIVE"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class ScanProfile(str, Enum):
    """Operational scan profile specifying the intensity and methodology."""

    BASELINE = "baseline"
    PASSIVE = "passive"
    ACTIVE = "active"


class ScanAuditEventType(str, Enum):
    """Audit trail event types for scanner execution tracking."""

    SCAN_REQUESTED = "scan_requested"
    SCAN_STARTED = "scan_started"
    SCAN_COMPLETED = "scan_completed"
    SCAN_FAILED = "scan_failed"
    SCAN_TIMED_OUT = "scan_timed_out"
    SCAN_CANCELLED = "scan_cancelled"
    AUTH_REJECTED = "auth_rejected"
    REPORT_GENERATED = "report_generated"
    REPORT_DOWNLOADED = "report_downloaded"
    SCAN_COMPARISON = "scan_comparison"
