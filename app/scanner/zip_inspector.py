"""Source Code ZIP Security Auditor.

Safely unpacks uploaded ZIP project archives, enforcing Zip-Slip path traversal defenses
and extraction size limits, then executes Bandit SAST and pip-audit SCA scans.
"""

import hashlib
import logging
import os
import shutil
import tempfile
import uuid
import zipfile
from pathlib import Path
from typing import Any

from app.scanner.adapters.bandit_adapter import BanditAdapter
from app.scanner.adapters.pip_audit_adapter import PipAuditAdapter
from app.scanner.grader import grade_posture

logger = logging.getLogger("vadl.scanner.zip_inspector")

# Safety limits for uploaded ZIP files
MAX_ZIP_BYTES = 25 * 1024 * 1024  # 25 MB
MAX_UNCOMPRESSED_BYTES = 60 * 1024 * 1024  # 60 MB
MAX_FILE_COUNT = 1500


class ZipAuditError(Exception):
    """Raised when an uploaded ZIP violates security constraints or extraction fails."""


def _compute_fingerprint(tool: str, rule: str, target: str) -> str:
    """Generate deterministic SHA-256 fingerprint for finding deduplication."""
    seed = f"{tool}:{rule}:{target}"
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()


def _is_safe_path(target_dir: Path, path: Path) -> bool:
    """Verify that path resolves strictly within target_dir (Zip Slip defense)."""
    try:
        resolved_target = target_dir.resolve()
        resolved_path = path.resolve()
        return resolved_path == resolved_target or resolved_target in resolved_path.parents
    except Exception:
        return False


def inspect_zip(zip_source: str | Path | Any, filename: str = "project.zip") -> dict[str, Any]:
    """Safely extract ZIP source archive and execute SAST + SCA analysis.

    Args:
        zip_source: File path, Path object, or file-like object containing ZIP data.
        filename: Original uploaded filename for reporting.

    Returns:
        dict containing:
            - filename: str
            - files_analyzed: int
            - has_dependencies: bool
            - findings: list[dict]
            - grade_result: dict
    """
    temp_dir = Path(tempfile.mkdtemp(prefix="vadl_audit_"))
    scan_id = str(uuid.uuid4())

    try:
        # Open ZIP file safely
        if hasattr(zip_source, "read"):
            # Ensure file pointer is at start
            if hasattr(zip_source, "seek"):
                zip_source.seek(0)
            zf = zipfile.ZipFile(zip_source)
        else:
            zf = zipfile.ZipFile(str(zip_source))

        with zf:
            infolist = zf.infolist()
            if len(infolist) > MAX_FILE_COUNT:
                raise ZipAuditError(
                    f"ZIP archive contains {len(infolist)} files, exceeding safety limit of {MAX_FILE_COUNT}."
                )

            total_uncompressed = 0
            for info in infolist:
                total_uncompressed += info.file_size
                if total_uncompressed > MAX_UNCOMPRESSED_BYTES:
                    raise ZipAuditError(
                        f"Uncompressed archive size exceeds limit of {MAX_UNCOMPRESSED_BYTES // (1024 * 1024)}MB (Zip bomb protection)."
                    )

                # Zip Slip path traversal check
                # Note: info.filename might contain forward or backslashes
                dest_path = (temp_dir / info.filename).resolve()
                if not _is_safe_path(temp_dir, dest_path):
                    raise ZipAuditError(
                        f"ZIP archive entry '{info.filename}' attempts path traversal outside target directory (Zip Slip defense)."
                    )

            # Safely extract all approved members
            zf.extractall(path=temp_dir)

        # Count extracted files
        all_files = [p for p in temp_dir.rglob("*") if p.is_file()]
        python_files = [p for p in all_files if p.suffix == ".py"]
        files_analyzed = len(all_files)

        findings: list[dict[str, Any]] = []

        # 1. Run Bandit SAST on extracted files
        bandit_adapter = BanditAdapter()
        is_avail, version, _ = bandit_adapter.detect_availability()
        if is_avail and (python_files or files_analyzed > 0):
            try:
                bandit_res = bandit_adapter.execute_scan(
                    scan_uuid=scan_id,
                    source_dir=str(temp_dir),
                    profile="baseline",
                    timeout_seconds=90,
                )
                raw_findings = bandit_adapter.parse_report(bandit_res.raw_report_path)
                for rf in raw_findings:
                    # Clean file path relative to temp_dir
                    rel_path = rf.file_path
                    if rel_path and str(temp_dir) in rel_path:
                        rel_path = os.path.relpath(rel_path, temp_dir)

                    findings.append(
                        {
                            "title": rf.title,
                            "description": rf.description,
                            "category": "Static Code Quality",
                            "cwe_id": rf.cwe_id or "CWE-20",
                            "severity": rf.severity,
                            "confidence": rf.confidence,
                            "target_component": rel_path or "source_code",
                            "file_path": rel_path,
                            "line_number": rf.line_number,
                            "evidence_snippet": rf.evidence_snippet,
                            "remediation_guidance": rf.remediation_guidance
                            or "Refactor code to avoid insecure patterns.",
                            "fingerprint": _compute_fingerprint(
                                "BANDIT", rf.tool_finding_id, rel_path or "app"
                            ),
                        }
                    )
            except Exception as exc:
                logger.warning(f"Bandit scan execution encountered error: {exc}")

        # 2. Check for requirements.txt for pip-audit SCA
        has_dependencies = False
        req_files = list(temp_dir.rglob("requirements*.txt"))
        if req_files:
            has_dependencies = True
            primary_req = req_files[0]
            pip_adapter = PipAuditAdapter()
            p_avail, p_version, _ = pip_adapter.detect_availability()
            if p_avail:
                try:
                    pip_res = pip_adapter.execute_scan(
                        scan_uuid=scan_id,
                        options={"requirements_file": str(primary_req)},
                        timeout_seconds=90,
                    )
                    raw_pip = pip_adapter.parse_report(pip_res.raw_report_path)
                    for rf in raw_pip:
                        findings.append(
                            {
                                "title": rf.title,
                                "description": rf.description,
                                "category": "Dependency Security",
                                "cwe_id": rf.cwe_id or "CWE-1395",
                                "severity": rf.severity,
                                "confidence": rf.confidence,
                                "target_component": rf.target_component,
                                "evidence_snippet": rf.evidence_snippet,
                                "remediation_guidance": rf.remediation_guidance
                                or "Upgrade vulnerable dependency to a patched version.",
                                "fingerprint": _compute_fingerprint(
                                    "PIP_AUDIT", rf.tool_finding_id, rf.target_component
                                ),
                            }
                        )
                except Exception as exc:
                    logger.warning(f"pip-audit execution encountered error: {exc}")

        categories = ["Static Code Quality"]
        if has_dependencies:
            categories.append("Dependency Security")

        grade_result = grade_posture(findings, categories_tested=categories, mode="ZIP")

        return {
            "filename": filename,
            "files_analyzed": files_analyzed,
            "python_files_count": len(python_files),
            "has_dependencies": has_dependencies,
            "findings": findings,
            "grade_result": grade_result,
        }

    finally:
        # Securely remove temporary extraction directory
        if temp_dir.exists():
            shutil.rmtree(temp_dir, ignore_errors=True)
