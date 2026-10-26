"""Security Posture Grader engine.

Calculates a deterministic 0-100 security score and letter grade (A+, A, B, C, D, F)
based on findings, missing security controls, and vulnerability severities.
"""

from typing import Any


def calculate_grade(score: int) -> str:
    """Map numeric score (0-100) to letter grade."""
    if score >= 95:
        return "A+"
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def grade_posture(
    findings: list[dict[str, Any]],
    categories_tested: list[str] | None = None,
    mode: str = "URL",
) -> dict[str, Any]:
    """Calculate overall security score, grade, and category breakdown.

    Deduction Weights:
    - CRITICAL finding: -20 pts
    - HIGH finding: -15 pts
    - MEDIUM finding: -8 pts
    - LOW finding: -3 pts
    - INFO finding: -1 pt

    Returns:
        dict containing:
            - score: int (0 to 100)
            - grade: str ("A+", "A", "B", "C", "D", "F")
            - deductions: list[dict]
            - category_scores: dict[str, int]
            - total_findings: int
            - summary: str
    """
    base_score = 100
    deductions: list[dict[str, Any]] = []

    # Category tracking: default category score is 100
    category_scores: dict[str, int] = {}
    if categories_tested:
        for cat in categories_tested:
            category_scores[cat] = 100

    severity_weights = {
        "CRITICAL": 20,
        "HIGH": 15,
        "MEDIUM": 8,
        "LOW": 3,
        "INFO": 1,
    }

    for finding in findings:
        severity = str(finding.get("severity", "LOW")).upper()
        weight = severity_weights.get(severity, 3)
        title = finding.get("title", "Security Finding")
        cat = finding.get("category", "General Security")

        if cat not in category_scores:
            category_scores[cat] = 100

        # Apply deduction to category score
        category_scores[cat] = max(0, category_scores[cat] - weight)

        # Apply deduction to overall score
        deductions.append(
            {
                "title": title,
                "category": cat,
                "severity": severity,
                "points_deducted": weight,
                "remediation": finding.get(
                    "remediation_guidance", "Apply standard security controls."
                ),
            }
        )

    total_deduction = sum(d["points_deducted"] for d in deductions)
    final_score = max(0, min(100, base_score - total_deduction))
    final_grade = calculate_grade(final_score)

    # Narrative summary
    if final_score >= 90:
        summary = "Strong defensive posture. Security headers and defensive controls meet best-practice baselines."
    elif final_score >= 75:
        summary = (
            "Moderate security posture. Minor missing headers or low-severity issues identified."
        )
    elif final_score >= 60:
        summary = "Degraded security posture. Critical security headers, cookies, or dependencies are missing."
    else:
        summary = "High-risk security posture. High/Critical vulnerabilities detected requiring urgent remediation."

    return {
        "score": final_score,
        "grade": final_grade,
        "mode": mode,
        "total_findings": len(findings),
        "deductions": deductions,
        "category_scores": category_scores,
        "summary": summary,
    }
