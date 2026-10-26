"""Tests for Source Code ZIP Security Auditor (Defenses and SAST/SCA Execution)."""

import io
import zipfile

import pytest

from app.scanner.zip_inspector import ZipAuditError, inspect_zip


def _create_in_memory_zip(file_dict: dict[str, str]) -> io.BytesIO:
    """Helper to construct an in-memory zip archive from filename -> content mapping."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for fname, content in file_dict.items():
            zf.writestr(fname, content)
    buf.seek(0)
    return buf


def test_zip_inspector_rejects_zip_slip_traversal():
    """Verify that Zip Slip attempts (traversing outside destination root) are rejected."""
    traversal_zip = _create_in_memory_zip(
        {
            "../../etc/passwd": "root:x:0:0:root:/root:/bin/bash\n",
            "app.py": "print('hello')",
        }
    )

    with pytest.raises(ZipAuditError) as exc_info:
        inspect_zip(traversal_zip, filename="malicious_slip.zip")

    assert "Zip Slip defense" in str(exc_info.value)


def test_zip_inspector_rejects_excessive_files():
    """Verify that archives with excessive file count (>1500) trigger Zip bomb rejection."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for i in range(1505):
            zf.writestr(f"file_{i}.txt", "test")
    buf.seek(0)

    with pytest.raises(ZipAuditError) as exc_info:
        inspect_zip(buf, filename="bomb.zip")

    assert "safety limit of 1500" in str(exc_info.value)


def test_zip_inspector_clean_python_archive():
    """Verify that a benign small Python project is audited cleanly."""
    clean_zip = _create_in_memory_zip(
        {
            "main.py": "def add(a: int, b: int) -> int:\n    return a + b\n\nif __name__ == '__main__':\n    print(add(2, 3))\n",
            "README.md": "# Sample Project\nClean Python project.\n",
        }
    )

    result = inspect_zip(clean_zip, filename="clean_app.zip")
    assert result["filename"] == "clean_app.zip"
    assert result["files_analyzed"] >= 2
    assert result["python_files_count"] >= 1
    assert result["grade_result"]["score"] >= 90
    assert result["grade_result"]["grade"] in ("A+", "A")
