"""Packages the Web Lab project into a clean, submission-ready ZIP archive.

Excludes all previous scan JSONs/PDFs, bytecode caches, virtual environments,
and temporary files, ensuring the archive is lightweight (<25MB) and ready
for GitHub upload or academic submission.
"""

import os
import sys
import zipfile
from pathlib import Path


def create_submission_zip(output_zip: str = "Web_Lab_Submission.zip"):
    root_dir = Path(".").resolve()
    zip_path = root_dir / output_zip

    # If the zip already exists, remove it first
    if zip_path.exists():
        zip_path.unlink()

    # Folders and file patterns to strictly exclude
    excluded_dirs = {
        ".venv",
        "venv",
        "env",
        ".git",
        ".system_generated",
        "__pycache__",
        ".pytest_cache",
        ".ruff_cache",
        ".idea",
        ".vscode",
        "Web_Lab_Submission",
    }

    excluded_files = {
        ".coverage",
        "output.txt",
        output_zip,
        "INSA_Project_Report.pdf",
        "INSA_Project_Report.md",
    }

    excluded_extensions = {".pyc", ".pyo", ".pyd", ".swp", ".swo", ".log"}

    added_files = 0
    total_uncompressed_bytes = 0

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for current_root, dirs, files in os.walk(root_dir):
            rel_root = Path(current_root).relative_to(root_dir)

            # Prune excluded directories
            dirs[:] = [
                d for d in dirs if d not in excluded_dirs and not d.startswith("__pycache__")
            ]

            # Check if we are inside the top-level reports/ storage directory
            is_inside_reports_storage = len(rel_root.parts) > 0 and rel_root.parts[0] == "reports"

            for file_name in files:
                rel_file_path = rel_root / file_name

                # Skip explicitly excluded files or extensions
                if file_name in excluded_files:
                    continue
                if any(file_name.endswith(ext) for ext in excluded_extensions):
                    continue
                if file_name.startswith(".coverage"):
                    continue

                # In reports storage folder, skip previous scan artifacts (json, pdf) but keep .gitkeep
                if is_inside_reports_storage and file_name != ".gitkeep":
                    continue

                full_path = Path(current_root) / file_name
                file_size = full_path.stat().st_size

                # Normalize archive path to forward slashes for cross-platform compatibility
                archive_name = str(rel_file_path).replace("\\", "/")
                zf.write(full_path, arcname=archive_name)

                added_files += 1
                total_uncompressed_bytes += file_size

    zip_size_bytes = zip_path.stat().st_size
    zip_size_mb = zip_size_bytes / (1024 * 1024)
    total_uncompressed_mb = total_uncompressed_bytes / (1024 * 1024)

    print("=================================================================")
    print("           WEB LAB SUBMISSION ARCHIVE CREATED")
    print("=================================================================")
    print(f"Archive Output       : {output_zip}")
    print(f"Total Files Added    : {added_files}")
    print(f"Uncompressed Size    : {total_uncompressed_mb:.2f} MB")
    print(f"Compressed ZIP Size  : {zip_size_mb:.2f} MB ({zip_size_bytes:,} bytes)")
    print(f"GitHub Limit Status  : {'PASS (< 25 MB)' if zip_size_mb < 25 else 'FAIL'}")
    print("=================================================================")


if __name__ == "__main__":
    out_name = sys.argv[1] if len(sys.argv) > 1 else "Web_Lab_Submission.zip"
    create_submission_zip(out_name)
