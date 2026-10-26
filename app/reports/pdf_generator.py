"""Professional PDF Security Assessment Report Generator using ReportLab (Phase 7).

Adheres to university cybersecurity reporting standards with safe XML escaping,
multi-page flowables, structured severity tables, and sanitized evidence blocks.
"""

from datetime import UTC, datetime
import html
import io
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.models.assessment import Assessment
from app.models.scanner import SecurityScan
from app.models.user import User


class NumberedCanvas(canvas.Canvas):
    """Two-pass canvas that computes and renders dynamic total page counts."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._saved_page_states: list[dict[str, Any]] = []

    def showPage(self) -> None:
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self) -> None:
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count: int) -> None:
        self.saveState()
        self.setFont("Helvetica-Bold", 8)
        self.setFillColor(colors.HexColor("#64748b"))

        # Running Header (pages > 1)
        if self._pageNumber > 1:
            self.drawString(54, 11 * inch - 36, "VADL — Vulnerability Assessment and Defense Lab")
            self.drawRightString(8.5 * inch - 54, 11 * inch - 36, "SECURITY ASSESSMENT REPORT")
            self.setStrokeColor(colors.HexColor("#cbd5e1"))
            self.setLineWidth(0.5)
            self.line(54, 11 * inch - 42, 8.5 * inch - 54, 11 * inch - 42)

        # Running Footer (all pages)
        self.setStrokeColor(colors.HexColor("#cbd5e1"))
        self.setLineWidth(0.5)
        self.line(54, 46, 8.5 * inch - 54, 46)

        self.setFont("Helvetica", 8)
        self.drawString(54, 34, "CONFIDENTIAL & PROPRIETARY — FOR AUTHORIZED LABORATORY USE ONLY")
        self.drawRightString(8.5 * inch - 54, 34, f"Page {self._pageNumber} of {page_count}")
        self.restoreState()


class PdfReportGenerator:
    """Renders professional cybersecurity assessment reports in PDF format."""

    def __init__(self) -> None:
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()

    def _setup_custom_styles(self) -> None:
        self.title_style = ParagraphStyle(
            "ReportTitle",
            parent=self.styles["Heading1"],
            fontName="Helvetica-Bold",
            fontSize=22,
            leading=26,
            textColor=colors.HexColor("#0f172a"),
            spaceAfter=6,
        )
        self.subtitle_style = ParagraphStyle(
            "ReportSubtitle",
            parent=self.styles["Normal"],
            fontName="Helvetica",
            fontSize=11,
            leading=14,
            textColor=colors.HexColor("#475569"),
            spaceAfter=14,
        )
        self.h1_style = ParagraphStyle(
            "SectionH1",
            parent=self.styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=14,
            leading=18,
            textColor=colors.HexColor("#1e293b"),
            spaceBefore=12,
            spaceAfter=6,
        )
        self.h2_style = ParagraphStyle(
            "SectionH2",
            parent=self.styles["Heading3"],
            fontName="Helvetica-Bold",
            fontSize=11,
            leading=14,
            textColor=colors.HexColor("#334155"),
            spaceBefore=8,
            spaceAfter=4,
        )
        self.body_style = ParagraphStyle(
            "ReportBody",
            parent=self.styles["Normal"],
            fontName="Helvetica",
            fontSize=9,
            leading=13,
            textColor=colors.HexColor("#1e293b"),
            spaceAfter=6,
        )
        self.callout_style = ParagraphStyle(
            "CalloutBody",
            parent=self.styles["Normal"],
            fontName="Helvetica-Oblique",
            fontSize=8.5,
            leading=12,
            textColor=colors.HexColor("#334155"),
        )
        self.code_style = ParagraphStyle(
            "ReportCode",
            parent=self.styles["Normal"],
            fontName="Courier",
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#0f172a"),
        )
        self.evidence_style = ParagraphStyle(
            "EvidenceCode",
            parent=self.styles["Normal"],
            fontName="Courier",
            fontSize=7.5,
            leading=9.5,
            textColor=colors.HexColor("#0f172a"),
            backColor=colors.HexColor("#f1f5f9"),
            borderColor=colors.HexColor("#94a3b8"),
            borderWidth=0.5,
            borderPadding=6,
            spaceBefore=3,
            spaceAfter=6,
        )

    @staticmethod
    def _safe_text(text: Any) -> str:
        """Escape text for safe inclusion in ReportLab XML-based Paragraphs."""
        if text is None:
            return "N/A"
        raw_str = str(text).strip()
        if not raw_str:
            return "N/A"
        escaped = html.escape(raw_str)
        return escaped.replace("\n", "<br/>")

    def _p(self, text: Any, style: ParagraphStyle | None = None) -> Paragraph:
        style = style or self.body_style
        return Paragraph(self._safe_text(text), style)

    def _code_p(self, text: Any) -> Paragraph:
        return Paragraph(self._safe_text(text), self.code_style)

    def _evidence_p(self, text: Any) -> Paragraph:
        raw_str = str(text).strip() if text else ""
        if len(raw_str) > 3500:
            raw_str = raw_str[:3500] + "\n\n... [Evidence truncated for report brevity]"
        return Paragraph(self._safe_text(raw_str), self.evidence_style)

    def build_scan_pdf(self, scan: SecurityScan, actor: User | None = None) -> bytes:
        """Generate a complete PDF security assessment report for a SecurityScan."""
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            leftMargin=54,
            rightMargin=54,
            topMargin=54,
            bottomMargin=54,
        )

        story: list[Any] = []
        now_str = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")

        # 1. Header & Title Block
        story.append(self._p("Vulnerability Assessment and Defense Lab (VADL)", self.subtitle_style))
        story.append(self._p(f"Security Scan Report: {scan.scanner_type.upper()}", self.title_style))
        story.append(
            self._p(
                f"Report ID: <b>{scan.uuid}</b> &nbsp;|&nbsp; Generated: <b>{now_str}</b> &nbsp;|&nbsp; Operator: <b>{actor.email if actor else 'System'}</b>",
                self.subtitle_style,
            )
        )
        story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#2563eb"), spaceAfter=14))

        # 2. Executive Scope & Target Identification
        story.append(self._p("1. Assessment Scope & Target Identification", self.h1_style))
        target_name = scan.target.name if scan.target else "Local Application Codebase"
        target_url = scan.target_url or (scan.target.base_url if scan.target else (scan.source_path or "app/"))
        is_auth = "Yes (Verified Local Lab Target)" if (scan.target and scan.target.is_authorized) else "Authorized Internal Scope"

        score_val = getattr(scan, "score", 100) or 100
        grade_val = getattr(scan, "grade", "A") or "A"
        grade_color = "#16a34a" if grade_val in ("A+", "A") else ("#d97706" if grade_val == "B" else "#dc2626")

        posture_box = [
            [
                self._p(f"<font size=14 color='{grade_color}'><b>SECURITY GRADE: {grade_val}</b></font> &nbsp;&nbsp; (Score: <b>{score_val} / 100</b>)"),
                self._p(f"Scan Mode: <b>{getattr(scan, 'scan_mode', 'AUTOMATED')}</b> &nbsp;|&nbsp; Findings: <b>{scan.total_findings}</b>"),
            ]
        ]
        t_posture = Table(posture_box, colWidths=[3.3 * inch, 3.3 * inch])
        t_posture.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
                ("BOX", (0, 0), (-1, -1), 1.5, colors.HexColor(grade_color)),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ])
        )
        story.append(t_posture)
        story.append(Spacer(1, 8))

        scope_data = [
            [self._p("Target Scope / Component:"), self._p(f"<b>{target_name}</b>")],
            [self._p("Target URI / Source Path:"), self._code_p(target_url)],
            [self._p("Target Edition:"), self._p(scan.target_edition or "N/A")],
            [self._p("Security Posture Grade:"), self._p(f"<font color='{grade_color}'><b>{grade_val} ({score_val}/100)</b></font>")],
            [self._p("Authorized Lab Scope:"), self._p(is_auth)],
            [self._p("Security Scanner Tool:"), self._p(f"<b>{scan.scanner_type}</b> (v{scan.tool_version or 'N/A'})")],
            [self._p("Operational Scan Profile:"), self._p(scan.scan_profile)],
            [self._p("Scan Execution Status:"), self._p(f"<b>{scan.status}</b>")],
            [self._p("Execution Duration:"), self._p(f"{scan.duration_seconds} seconds" if scan.duration_seconds is not None else "N/A")],
        ]
        t_scope = Table(scope_data, colWidths=[1.8 * inch, 4.8 * inch])
        t_scope.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ])
        )
        story.append(t_scope)
        story.append(Spacer(1, 12))

        # 3. Assessment Methodology
        story.append(self._p("2. Assessment Methodology", self.h1_style))
        methodology_text = (
            f"This automated security evaluation was conducted using <b>{scan.scanner_type.upper()}</b> "
            f"operating under the <b>{scan.scan_profile}</b> profile within the isolated laboratory environment. "
            "Testing activities were strictly bounded to approved local components and verified against the "
            "authorized target registry prior to execution. Findings were normalized into canonical schema "
            "and deduplicated using stable SHA-256 fingerprinting."
        )
        story.append(self._p(methodology_text))
        story.append(Spacer(1, 10))

        # 4. Findings Summary & Severity Distribution
        story.append(self._p("3. Findings Summary & Severity Distribution", self.h1_style))
        sev_data = [
            [self._p("<b>Severity Level</b>"), self._p("<b>Count</b>"), self._p("<b>Classification Criteria</b>")],
            [self._p("<font color='#dc2626'><b>CRITICAL</b></font>"), self._p(str(scan.critical_count)), self._p("Direct remote code execution or widespread authentication compromise.")],
            [self._p("<font color='#ef4444'><b>HIGH</b></font>"), self._p(str(scan.high_count)), self._p("SQL injection, IDOR with data leakage, or stored privilege escalation.")],
            [self._p("<font color='#f59e0b'><b>MEDIUM</b></font>"), self._p(str(scan.medium_count)), self._p("Reflected cross-site scripting or missing CSRF protections.")],
            [self._p("<font color='#06b6d4'><b>LOW</b></font>"), self._p(str(scan.low_count)), self._p("Security header omissions or verbose server error banners.")],
            [self._p("<font color='#64748b'><b>INFORMATIONAL</b></font>"), self._p(str(scan.info_count)), self._p("Architectural observations and non-exploitable configuration notes.")],
            [self._p("<b>TOTAL FINDINGS</b>"), self._p(f"<b>{scan.total_findings}</b>"), self._p("Consolidated normalized findings count across all categories.")],
        ]
        t_sev = Table(sev_data, colWidths=[1.8 * inch, 1.0 * inch, 3.8 * inch])
        t_sev.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                ("BACKGROUND", (0, -1), (-1, -1), colors.HexColor("#f1f5f9")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#94a3b8")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ])
        )
        story.append(t_sev)
        story.append(Spacer(1, 14))

        # 5. Detailed Findings & Sanitized Evidence
        story.append(self._p("4. Detailed Technical Findings", self.h1_style))
        if not scan.findings:
            story.append(
                self._p(
                    "No vulnerability findings were identified by the automated scanner during this execution run.",
                    self.callout_style,
                )
            )
            story.append(Spacer(1, 10))
        else:
            for idx, finding in enumerate(scan.findings, start=1):
                sev_color = "#dc2626" if finding.severity == "CRITICAL" else (
                    "#ef4444" if finding.severity == "HIGH" else (
                        "#f59e0b" if finding.severity == "MEDIUM" else (
                            "#06b6d4" if finding.severity == "LOW" else "#64748b"
                        )
                    )
                )
                title_html = f"Finding #{idx}: {finding.title} &nbsp; [<font color='{sev_color}'><b>{finding.severity}</b></font>]"
                f_heading = self._p(title_html, self.h2_style)

                f_meta = [
                    [self._p("Vulnerability ID:"), self._p(f"<b>{getattr(finding, 'tool_finding_id', getattr(finding, 'vulnerability_identifier', 'N/A'))}</b>"),
                     self._p("Confidence:"), self._p(finding.confidence or "MEDIUM")],
                    [self._p("CWE Identifier:"), self._p(finding.cwe_id or "N/A"),
                     self._p("OWASP Category:"), self._p(finding.owasp_category or "N/A")],
                    [self._p("Affected Component:"), self._code_p(finding.target_component or "N/A"),
                     self._p("Lifecycle Status:"), self._p(f"<b>{finding.status}</b>")],
                ]
                t_fmeta = Table(f_meta, colWidths=[1.4 * inch, 1.9 * inch, 1.4 * inch, 1.9 * inch])
                t_fmeta.setStyle(
                    TableStyle([
                        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
                        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                        ("TOPPADDING", (0, 0), (-1, -1), 3),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                    ])
                )
                story.append(KeepTogether([f_heading, t_fmeta]))
                story.append(Spacer(1, 4))

                if finding.description:
                    story.append(self._p(f"<b>Description:</b> {finding.description}"))

                rem_guidance = getattr(finding, "remediation_guidance", getattr(finding, "remediation_advice", None))
                if rem_guidance:
                    story.append(self._p(f"<b>Remediation Guidance:</b> {rem_guidance}"))

                if finding.evidence_snippet:
                    story.append(self._p("<b>Sanitized Technical Evidence:</b>"))
                    story.append(self._evidence_p(finding.evidence_snippet))

                story.append(Spacer(1, 10))

        # 6. Remediation & Verification Summary
        story.append(self._p("5. Remediation Recommendations & Verification Workflow", self.h1_style))
        remediation_text = (
            "To successfully remediate findings discovered during testing, engineers must apply input "
            "parameterization (SQL injection), output contextual encoding (XSS), server-side ownership "
            "authorization checks (IDOR), and defensive HTTP security headers. Defenses must not be considered "
            "verified through manual assertions alone; they must undergo automated regression verification "
            "via the VADL Phase 5 remediation engine."
        )
        story.append(self._p(remediation_text))
        story.append(Spacer(1, 10))

        # 7. Limitations & Interpretation of Results
        story.append(self._p("6. Limitations & Interpretation of Results", self.h1_style))
        disclaimer_text = (
            "<b>IMPORTANT SECURITY NOTICE:</b> The absence of automated findings does <i>not</i> prove an "
            "application is completely secure. Automated tools and scenario adapters evaluate designated rule subsets "
            "and local execution paths only. Business-logic flaws, complex race conditions, and zero-day attack vectors "
            "may remain undetected. Results must be interpreted in conjunction with thorough architecture review and manual penetration testing."
        )
        t_disc = Table([[self._p(disclaimer_text, self.callout_style)]], colWidths=[6.6 * inch])
        t_disc.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#fffbeb")),
                ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#d97706")),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ])
        )
        story.append(t_disc)
        story.append(Spacer(1, 10))

        # 8. Conclusion & Sign-Off
        story.append(self._p("7. Conclusion & Recommended Next Steps", self.h1_style))
        conclusion_text = (
            f"The evaluation for scan <b>#{scan.id}</b> concluded with status <b>{scan.status}</b>. "
            f"A total of <b>{scan.total_findings}</b> normalized findings were recorded. "
            "Recommended next steps: (1) Review confirmed critical and high severity findings; "
            "(2) Link findings to remediation tickets; (3) Deploy hardened code to the secure target edition; "
            "and (4) Re-execute automated verification regression suites."
        )
        story.append(self._p(conclusion_text))

        doc.build(story, canvasmaker=NumberedCanvas)
        return buffer.getvalue()

    def build_assessment_pdf(self, assessment: Assessment, actor: User | None = None) -> bytes:
        """Generate a complete PDF report for an offensive Assessment execution."""
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            leftMargin=54,
            rightMargin=54,
            topMargin=54,
            bottomMargin=54,
        )

        story: list[Any] = []
        now_str = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")

        # 1. Header & Title Block
        story.append(self._p("Vulnerability Assessment and Defense Lab (VADL)", self.subtitle_style))
        story.append(self._p("Offensive Assessment Security Report", self.title_style))
        story.append(
            self._p(
                f"Assessment ID: <b>{assessment.uuid}</b> &nbsp;|&nbsp; Generated: <b>{now_str}</b> &nbsp;|&nbsp; Operator: <b>{actor.email if actor else 'System'}</b>",
                self.subtitle_style,
            )
        )
        story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#7c3aed"), spaceAfter=14))

        # 2. Scope & Target Information
        story.append(self._p("1. Assessment Scope & Target Identification", self.h1_style))
        target_name = assessment.target.name if assessment.target else f"Target #{assessment.target_id}"
        target_url = assessment.target.base_url if assessment.target else "N/A"

        scope_data = [
            [self._p("Target Scope:"), self._p(f"<b>{target_name}</b>")],
            [self._p("Target Base URL:"), self._code_p(target_url)],
            [self._p("Target Edition:"), self._p(assessment.target_edition)],
            [self._p("Execution Status:"), self._p(f"<b>{assessment.status}</b>")],
            [self._p("Total Tests Executed:"), self._p(str(assessment.total_tests))],
            [self._p("Confirmed Vulnerabilities:"), self._p(f"<font color='#dc2626'><b>{assessment.confirmed_vulnerabilities}</b></font>")],
            [self._p("Passed / Neutralized Checks:"), self._p(f"<font color='#16a34a'><b>{assessment.passed_checks}</b></font>")],
            [self._p("Execution Duration:"), self._p(f"{assessment.duration_seconds} seconds" if assessment.duration_seconds is not None else "N/A")],
        ]
        t_scope = Table(scope_data, colWidths=[2.0 * inch, 4.6 * inch])
        t_scope.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ])
        )
        story.append(t_scope)
        story.append(Spacer(1, 12))

        # 3. Assessment Methodology
        story.append(self._p("2. Assessment Methodology", self.h1_style))
        story.append(
            self._p(
                "Controlled offensive test cases were executed by scenario adapters against the specified target. "
                "Each scenario adapter delivers approved attack payloads (e.g., boolean SQL injection, XSS vectors, IDOR object probes, HTTP header inspections) "
                "to empirically determine if vulnerabilities can be exploited or if defensive controls properly neutralize the payload."
            )
        )
        story.append(Spacer(1, 10))

        # 4. Scenario Results Table
        story.append(self._p("3. Scenario Execution Results", self.h1_style))
        res_data = [
            [self._p("<b>Scenario ID</b>"), self._p("<b>Scenario Title</b>"), self._p("<b>Outcome</b>"), self._p("<b>Duration</b>")],
        ]
        for r in assessment.results:
            outcome_val = getattr(r, "outcome", getattr(r, "status", "UNKNOWN"))
            status_color = "#dc2626" if outcome_val in ("CONFIRMED_VULNERABLE", "VULNERABILITY_CONFIRMED") else ("#16a34a" if outcome_val in ("PASSED", "SECURITY_CHECK_PASSED") else "#d97706")
            res_data.append([
                self._p(f"<b>{r.scenario_id}</b>"),
                self._p(getattr(r, "scenario_name", None) or r.scenario_id),
                self._p(f"<font color='{status_color}'><b>{outcome_val}</b></font>"),
                self._p(f"{r.duration_ms} ms" if getattr(r, "duration_ms", None) else "N/A"),
            ])
        t_res = Table(res_data, colWidths=[1.5 * inch, 2.7 * inch, 1.6 * inch, 0.8 * inch])
        t_res.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#94a3b8")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ])
        )
        story.append(t_res)
        story.append(Spacer(1, 12))

        # 5. Detailed Test Findings & Evidence
        story.append(self._p("4. Detailed Scenario Test Evidence", self.h1_style))
        for r in assessment.results:
            outcome_val = getattr(r, "outcome", getattr(r, "status", "UNKNOWN"))
            status_color = "#dc2626" if outcome_val in ("CONFIRMED_VULNERABLE", "VULNERABILITY_CONFIRMED") else ("#16a34a" if outcome_val in ("PASSED", "SECURITY_CHECK_PASSED") else "#d97706")
            sc_title = getattr(r, "scenario_name", None) or r.scenario_id
            r_heading = self._p(f"{r.scenario_id}: {sc_title} &nbsp; [<font color='{status_color}'><b>{outcome_val}</b></font>]", self.h2_style)

            cwe = getattr(r, "cwe_id", None)
            meta_parts: list[Any] = [r_heading]
            if cwe:
                meta_parts.append(self._p(f"<b>CWE:</b> {cwe} &nbsp;|&nbsp; <b>OWASP:</b> {getattr(r, 'owasp_category', 'N/A')}"))
            story.append(KeepTogether(meta_parts))

            desc = getattr(r, "description", None)
            if desc:
                story.append(self._p(f"<b>Description:</b> {desc}"))
            guidance = getattr(r, "remediation_guidance", None)
            if guidance:
                story.append(self._p(f"<b>Remediation:</b> {guidance}"))
            ev_data = getattr(r, "evidence", getattr(r, "sanitized_evidence", None))
            if ev_data:
                story.append(self._p("<b>Sanitized Test Evidence:</b>"))
                story.append(self._evidence_p(ev_data))
            story.append(Spacer(1, 8))

        # 6. Limitations & Disclaimer
        story.append(self._p("5. Limitations & Interpretation of Results", self.h1_style))
        disclaimer_text = (
            "<b>LABORATORY BOUNDARY NOTICE:</b> Test results confirm the behavioral state of designated training scenarios "
            "under simulated attack payloads. Passing tests confirm that the specific attack vectors tested were neutralized. "
            "They do not guarantee complete protection against unmodeled vectors or zero-day exploitation."
        )
        t_disc = Table([[self._p(disclaimer_text, self.callout_style)]], colWidths=[6.6 * inch])
        t_disc.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#fffbeb")),
                ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#d97706")),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ])
        )
        story.append(t_disc)

        doc.build(story, canvasmaker=NumberedCanvas)
        return buffer.getvalue()

    def build_comparison_pdf(self, diff: dict[str, Any], actor: User | None = None) -> bytes:
        """Generate a scan comparison differential report in PDF format."""
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            leftMargin=54,
            rightMargin=54,
            topMargin=54,
            bottomMargin=54,
        )

        story: list[Any] = []
        now_str = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")

        story.append(self._p("Vulnerability Assessment and Defense Lab (VADL)", self.subtitle_style))
        story.append(self._p("Scan Comparison & Trend Report", self.title_style))
        story.append(
            self._p(
                f"Generated: <b>{now_str}</b> &nbsp;|&nbsp; Target: <b>{diff.get('target_name', 'N/A')}</b> &nbsp;|&nbsp; Operator: <b>{actor.email if actor else 'System'}</b>",
                self.subtitle_style,
            )
        )
        story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0891b2"), spaceAfter=14))

        # Overview Table
        story.append(self._p("1. Comparison Overview & Target Parameters", self.h1_style))
        sa = diff.get("scan_a") or diff.get("assessment_a") or {}
        sb = diff.get("scan_b") or diff.get("assessment_b") or {}

        comp_data = [
            [self._p("Target Scope:"), self._p(f"<b>{diff.get('target_name')}</b> (Target #{diff.get('target_id')})")],
            [self._p("Baseline Run:"), self._p(f"ID #{sa.get('id')} ({sa.get('created_at')}) &mdash; Status: <b>{sa.get('status')}</b>")],
            [self._p("Comparison Run:"), self._p(f"ID #{sb.get('id')} ({sb.get('created_at')}) &mdash; Status: <b>{sb.get('status')}</b>")],
            [self._p("Comparison Conclusive:"), self._p("<b>Yes</b>" if diff.get("is_conclusive") else "<font color='#dc2626'><b>No (Caveats apply)</b></font>")],
        ]
        t_comp = Table(comp_data, colWidths=[1.8 * inch, 4.8 * inch])
        t_comp.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ])
        )
        story.append(t_comp)
        story.append(Spacer(1, 12))

        # Metrics Breakdown
        story.append(self._p("2. Differential Findings Summary", self.h1_style))
        counts = diff.get("counts", {})
        diff_data = [
            [self._p("<b>Category</b>"), self._p("<b>Count</b>"), self._p("<b>Description</b>")],
            [self._p("<font color='#dc2626'><b>Newly Detected</b></font>"), self._p(str(counts.get("new", 0))), self._p("Findings present in comparison scan but absent in baseline.")],
            [self._p("<font color='#16a34a'><b>Resolved / No Longer Detected</b></font>"), self._p(str(counts.get("resolved", counts.get("remediated", 0)))), self._p("Findings present in baseline but no longer observed in comparison.")],
            [self._p("<font color='#f59e0b'><b>Persistent Findings</b></font>"), self._p(str(counts.get("persistent", 0))), self._p("Findings observed across both baseline and comparison executions.")],
            [self._p("<b>Severity Changes</b>"), self._p(str(counts.get("severity_changes", 0))), self._p("Persistent findings whose normalized severity rating changed.")],
        ]
        t_diff = Table(diff_data, colWidths=[2.0 * inch, 0.8 * inch, 3.8 * inch])
        t_diff.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#94a3b8")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ])
        )
        story.append(t_diff)
        story.append(Spacer(1, 12))

        # Caveats & Disclaimers
        story.append(self._p("3. Caveats & Analytical Limitations", self.h1_style))
        caveats = diff.get("caveats", [])
        if caveats:
            c_items = "".join([f"&bull; {html.escape(c)}<br/>" for c in caveats])
            t_cav = Table([[self._p(c_items, self.callout_style)]], colWidths=[6.6 * inch])
            t_cav.setStyle(
                TableStyle([
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#fffbeb")),
                    ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#d97706")),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ])
            )
            story.append(t_cav)

        doc.build(story, canvasmaker=NumberedCanvas)
        return buffer.getvalue()
