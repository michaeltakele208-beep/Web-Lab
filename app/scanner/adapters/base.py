"""Abstract base class and execution data containers for automated security scanner adapters (Phase 6)."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from app.scanner.semantics import ScannerType


class ScannerError(Exception):
    """Base exception for scanner integration failures."""

    pass


class ToolNotAvailableError(ScannerError):
    """Raised when a requested scanning tool is not installed or runtime is unavailable."""

    pass


class ScannerTimeoutError(ScannerError):
    """Raised when scanner execution exceeds configured execution timeout limit."""

    pass


class ScannerExecutionError(ScannerError):
    """Raised when scanner tool exits with an unexpected or catastrophic failure."""

    pass


class ReportParsingError(ScannerError):
    """Raised when scanner output report is missing, empty, or unparseable JSON."""

    pass


@dataclass
class RawFinding:
    """Intermediate finding extracted from tool-specific report before common schema normalization."""

    tool_finding_id: str
    title: str
    description: str
    raw_severity: str
    raw_confidence: str | None = None
    category: str | None = None
    cwe_id: str | None = None
    owasp_category: str | None = None
    target_component: str = ""
    file_path: str | None = None
    line_number: int | None = None
    evidence_snippet: str | None = None
    remediation_guidance: str | None = None
    advisory_url: str | None = None
    extra_metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanExecutionResult:
    """Structured result returned by a scanner adapter execution."""

    scanner_type: ScannerType
    exit_code: int
    tool_version: str | None
    tool_configuration: dict[str, Any]
    raw_report_path: str | None
    findings: list[RawFinding] = field(default_factory=list)
    stdout: str = ""
    stderr: str = ""
    error_message: str | None = None


class BaseScannerAdapter(ABC):
    """Abstract contract for security scanner tool integration adapters."""

    scanner_type: ScannerType

    @abstractmethod
    def detect_availability(self) -> tuple[bool, str | None, str | None]:
        """Check if the tool is available.

        Returns:
            tuple: (is_available, detected_version, unavailable_reason)
        """
        pass

    @abstractmethod
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
        """Execute a controlled scan and return structured execution result and raw findings."""
        pass
