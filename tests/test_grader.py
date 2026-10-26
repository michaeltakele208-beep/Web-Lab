"""Tests for the Security Posture Grader engine."""

from app.scanner.grader import calculate_grade, grade_posture


def test_calculate_grade_thresholds():
    """Verify grade calculation maps exact score thresholds to letter grades."""
    assert calculate_grade(100) == "A+"
    assert calculate_grade(95) == "A+"
    assert calculate_grade(94) == "A"
    assert calculate_grade(90) == "A"
    assert calculate_grade(89) == "B"
    assert calculate_grade(80) == "B"
    assert calculate_grade(79) == "C"
    assert calculate_grade(70) == "C"
    assert calculate_grade(69) == "D"
    assert calculate_grade(60) == "D"
    assert calculate_grade(59) == "F"
    assert calculate_grade(0) == "F"


def test_grade_posture_clean():
    """Verify zero findings yields a perfect score 100 with A+ grade."""
    result = grade_posture([])
    assert result["score"] == 100
    assert result["grade"] == "A+"
    assert result["total_findings"] == 0
    assert len(result["deductions"]) == 0


def test_grade_posture_deductions_and_categories():
    """Verify deductions are correctly calculated across severity levels and categories."""
    findings = [
        {
            "title": "Missing CSP",
            "category": "Security Headers",
            "severity": "HIGH",
            "remediation_guidance": "Add Content-Security-Policy header",
        },
        {
            "title": "Missing HSTS",
            "category": "Transport & TLS",
            "severity": "MEDIUM",
            "remediation_guidance": "Add HSTS header",
        },
        {
            "title": "Server Banner",
            "category": "Information Disclosure",
            "severity": "LOW",
            "remediation_guidance": "Strip Server header",
        },
    ]

    result = grade_posture(
        findings,
        categories_tested=["Security Headers", "Transport & TLS", "Information Disclosure"],
        mode="URL",
    )

    # HIGH (-15) + MEDIUM (-8) + LOW (-3) = -26 -> 100 - 26 = 74
    assert result["score"] == 74
    assert result["grade"] == "C"
    assert result["total_findings"] == 3
    assert result["category_scores"]["Security Headers"] == 85
    assert result["category_scores"]["Transport & TLS"] == 92
    assert result["category_scores"]["Information Disclosure"] == 97
