"""Renders the Security & Compliance Report as JSON and a polished, dark-branded PDF from
one ReportContext — the board/auditor-ready artifact extension of the Audit Mode evidence
pack (app.audit.report_builder), which this module deliberately mirrors in structure
(reportlab, same no-system-binary-dependency rationale) while using Cordon's own dark visual
identity (navy background, the "C" mark, brand-blue accents) instead of the evidence pack's
plain light/print styling, since this artifact is meant to be read on screen by a board
member as much as printed for an auditor.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from io import BytesIO
from pathlib import Path
from xml.sax.saxutils import escape as xml_escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    HRFlowable,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.reports.executive_summary import ExecutiveSummary
from app.reports.gather import ReportMetrics

_LOGO_PATH = Path(__file__).parent / "assets" / "cordon-logo.png"

# Matches the marketing site's dark palette exactly (site/app/globals.css) so the PDF reads
# as the same product, not a generic report template.
NAVY_BG = colors.HexColor("#05090f")
CARD_BG = colors.HexColor("#0f1b2d")
BORDER = colors.HexColor("#1e293b")
BRAND_BLUE = colors.HexColor("#3b82f6")
TEXT_WHITE = colors.HexColor("#f8fafc")
TEXT_MUTED = colors.HexColor("#94a3b8")

METHODOLOGY_NOTE = (
    "This report aggregates only Cordon's own already-persisted detections and program "
    "activity for this account over the stated period: analyzed emails and their "
    "deterministic verdicts, autonomous-response actions that actually executed, "
    "intrusion/exfiltration incidents, early-warning alerts, phishing-simulation outcomes, "
    "and control-framework references from this period's detections. Estimated exposure "
    "avoided is a deterministic, assumptions-based point estimate, not a guarantee or an "
    "audited financial figure; see GET /api/risk/financial for the full assumption set. "
    "This reflects automated detections only and is not a substitute for full control "
    "testing, a financial audit, or manual review."
)


@dataclass(frozen=True)
class ReportContext:
    account_name: str
    period_start: datetime
    period_end: datetime
    generated_at: datetime
    metrics: ReportMetrics
    executive_summary: ExecutiveSummary


def _fmt_pct(value: float) -> str:
    return f"{value:g}%"


def build_json_report(ctx: ReportContext) -> bytes:
    m = ctx.metrics
    payload = {
        "cordon_security_compliance_report": {
            "account_name": ctx.account_name,
            "period_start": ctx.period_start.isoformat(),
            "period_end": ctx.period_end.isoformat(),
            "generated_at": ctx.generated_at.isoformat(),
            "executive_summary": {
                "text": ctx.executive_summary.text,
                "source": ctx.executive_summary.source,
                "model": ctx.executive_summary.model,
            },
            "emails_analyzed": m.emails_analyzed,
            "verdict_breakdown": {
                "malicious": m.verdict_breakdown.malicious,
                "suspicious": m.verdict_breakdown.suspicious,
                "safe": m.verdict_breakdown.safe,
            },
            "threats_detected": m.threats_detected,
            "threats_contained": m.threats_contained,
            "exposure_avoided_usd": m.exposure_avoided_usd,
            "exposure_by_attack_type": [
                {
                    "attack_type": e.attack_type,
                    "count": e.count,
                    "avg_loss_usd": e.avg_loss_usd,
                    "subtotal_usd": e.subtotal_usd,
                }
                for e in m.exposure_by_attack_type
            ],
            "incidents_detected": m.incidents_detected,
            "early_warning_alerts_raised": m.early_warning_alerts_raised,
            "human_risk": {
                "campaigns_run": m.human_risk.campaigns_run,
                "employees_tested": m.human_risk.employees_tested,
                "employees_clicked": m.human_risk.employees_clicked,
                "employees_reported": m.human_risk.employees_reported,
                "employees_flagged_for_training": m.human_risk.employees_flagged_for_training,
            },
            "framework_coverage": [
                {
                    "framework_key": r.framework_key,
                    "framework_name": r.framework_name,
                    "total_controls": r.total_controls,
                    "covered_controls": r.covered_controls,
                    "coverage_pct": r.coverage_pct,
                }
                for r in m.framework_coverage
            ],
            "has_any_activity": m.has_any_activity,
            "methodology": METHODOLOGY_NOTE,
        }
    }
    return json.dumps(payload, indent=2).encode("utf-8")


def _draw_page_chrome(canvas, doc) -> None:
    """Dark background + logo header + muted footer on every page — a canvas-level callback
    (reportlab's documented way to paint something behind/around the flowable content) since
    platypus has no "page background color" concept of its own."""
    canvas.saveState()
    page_width, page_height = letter
    canvas.setFillColor(NAVY_BG)
    canvas.rect(0, 0, page_width, page_height, stroke=0, fill=1)

    logo_size = 0.32 * inch
    margin = 0.75 * inch
    top = page_height - margin
    if _LOGO_PATH.exists():
        canvas.drawImage(
            str(_LOGO_PATH),
            margin,
            top - logo_size + 0.05 * inch,
            width=logo_size,
            height=logo_size,
            mask="auto",
        )
    canvas.setFillColor(TEXT_WHITE)
    canvas.setFont("Helvetica-Bold", 12)
    canvas.drawString(margin + logo_size + 0.12 * inch, top - logo_size + 0.14 * inch, "CORDON")

    canvas.setFillColor(TEXT_MUTED)
    canvas.setFont("Helvetica", 8)
    canvas.drawRightString(
        page_width - margin, 0.5 * inch, f"Page {doc.page} · Generated by Cordon Cybersecurity"
    )
    canvas.restoreState()


def _style(name: str, *, size: int, color, bold: bool = False, leading: int | None = None) -> ParagraphStyle:
    return ParagraphStyle(
        name,
        fontName="Helvetica-Bold" if bold else "Helvetica",
        fontSize=size,
        leading=leading or int(size * 1.4),
        textColor=color,
    )


def _stat_table(rows: list[tuple[str, str]]) -> Table:
    """A row of stat cards (label over value), styled as dark bordered panels. Each cell's
    content is a list of flowables, which reportlab stacks vertically within that cell."""
    label_style = _style("StatLabel", size=8, color=TEXT_MUTED)
    value_style = _style("StatValue", size=16, color=TEXT_WHITE, bold=True)
    row_cells = [
        [Paragraph(xml_escape(label), label_style), Spacer(1, 0.05 * inch), Paragraph(xml_escape(value), value_style)]
        for label, value in rows
    ]
    table = Table([row_cells], colWidths=[1.55 * inch] * len(rows))
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), CARD_BG),
                ("BOX", (0, 0), (-1, -1), 0.75, BORDER),
                ("INNERGRID", (0, 0), (-1, -1), 0.75, BORDER),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (-1, -1), 10),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
            ]
        )
    )
    return table


def build_pdf_report(ctx: ReportContext) -> bytes:
    m = ctx.metrics
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        title=f"Cordon Security & Compliance Report - {ctx.account_name}",
        topMargin=1.4 * inch,
        bottomMargin=0.9 * inch,
        leftMargin=0.75 * inch,
        rightMargin=0.75 * inch,
    )

    title_style = _style("Title", size=22, color=TEXT_WHITE, bold=True, leading=26)
    subtitle_style = _style("Subtitle", size=10, color=TEXT_MUTED)
    heading_style = _style("Heading", size=13, color=BRAND_BLUE, bold=True, leading=18)
    body_style = _style("Body", size=9.5, color=TEXT_WHITE, leading=14)
    muted_style = _style("Muted", size=8, color=TEXT_MUTED, leading=12)

    elements: list = [
        Paragraph("Security &amp; Compliance Report", title_style),
        Spacer(1, 0.08 * inch),
        Paragraph(xml_escape(ctx.account_name), subtitle_style),
        Paragraph(
            f"Period: {ctx.period_start:%Y-%m-%d} to {ctx.period_end:%Y-%m-%d} &nbsp;&nbsp;"
            f"Generated: {ctx.generated_at:%Y-%m-%d %H:%M} UTC",
            subtitle_style,
        ),
        Spacer(1, 0.25 * inch),
        HRFlowable(width="100%", color=BORDER, thickness=0.75),
        Spacer(1, 0.2 * inch),
        Paragraph("Executive Summary", heading_style),
        Spacer(1, 0.08 * inch),
        Paragraph(xml_escape(ctx.executive_summary.text), body_style),
        Spacer(1, 0.06 * inch),
        Paragraph(
            "Generated by Cordon's AI analyst, grounded only in the figures in this report."
            if ctx.executive_summary.source == "llm"
            else "Generated directly from the figures in this report (no AI narrative layer).",
            muted_style,
        ),
        Spacer(1, 0.3 * inch),
    ]

    if not m.has_any_activity:
        # The executive summary above already states this plainly — no need to repeat it,
        # and no stat grid full of zeros to show.
        pass
    else:
        elements.append(
            _stat_table(
                [
                    ("EMAILS ANALYZED", str(m.emails_analyzed)),
                    ("THREATS DETECTED", str(m.threats_detected)),
                    ("THREATS CONTAINED", str(m.threats_contained)),
                    ("EXPOSURE AVOIDED", f"${m.exposure_avoided_usd:,.0f}"),
                ]
            )
        )
        elements.append(Spacer(1, 0.3 * inch))

        elements.append(Paragraph("Verdict Breakdown", heading_style))
        elements.append(Spacer(1, 0.08 * inch))
        verdict_table = Table(
            [
                ["Malicious", "Suspicious", "Safe"],
                [
                    str(m.verdict_breakdown.malicious),
                    str(m.verdict_breakdown.suspicious),
                    str(m.verdict_breakdown.safe),
                ],
            ],
            colWidths=[1.6 * inch] * 3,
        )
        verdict_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), CARD_BG),
                    ("TEXTCOLOR", (0, 0), (-1, 0), TEXT_MUTED),
                    ("TEXTCOLOR", (0, 1), (-1, 1), TEXT_WHITE),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("FONTNAME", (0, 1), (-1, 1), "Helvetica-Bold"),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("GRID", (0, 0), (-1, -1), 0.5, BORDER),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ]
            )
        )
        elements.append(verdict_table)
        elements.append(Spacer(1, 0.3 * inch))

        elements.append(Paragraph("Intrusion &amp; Early-Warning", heading_style))
        elements.append(Spacer(1, 0.08 * inch))
        elements.append(
            Paragraph(
                f"{m.incidents_detected} intrusion/data-exfiltration incident(s) detected. "
                f"{m.early_warning_alerts_raised} early-warning alert(s) raised (an attack "
                "forming, flagged before it became a full incident).",
                body_style,
            )
        )
        elements.append(Spacer(1, 0.3 * inch))

        hr = m.human_risk
        elements.append(Paragraph("Human Risk / Phishing Simulation", heading_style))
        elements.append(Spacer(1, 0.08 * inch))
        if hr.campaigns_run > 0:
            elements.append(
                Paragraph(
                    f"{hr.campaigns_run} campaign(s) run against {hr.employees_tested} "
                    f"employee(s). {hr.employees_clicked} clicked the simulated lure, "
                    f"{hr.employees_reported} reported it, and "
                    f"{hr.employees_flagged_for_training} were flagged for follow-up training.",
                    body_style,
                )
            )
        else:
            elements.append(
                Paragraph("No phishing-simulation campaigns were run in this period.", body_style)
            )
        elements.append(Spacer(1, 0.3 * inch))

    elements.append(PageBreak())
    elements.append(Paragraph("Control-Framework Coverage", heading_style))
    elements.append(Spacer(1, 0.08 * inch))
    elements.append(
        Paragraph(
            "Share of each framework's control set with at least one supporting detection "
            "from this period's analyzed emails.",
            muted_style,
        )
    )
    elements.append(Spacer(1, 0.1 * inch))

    fw_table_data = [["Framework", "Controls Covered", "Coverage"]]
    for row in m.framework_coverage:
        fw_table_data.append(
            [
                Paragraph(xml_escape(row.framework_name), body_style),
                f"{row.covered_controls} / {row.total_controls}",
                _fmt_pct(row.coverage_pct),
            ]
        )
    fw_table = Table(fw_table_data, colWidths=[2.8 * inch, 1.8 * inch, 1.2 * inch], repeatRows=1)
    fw_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), CARD_BG),
                ("TEXTCOLOR", (0, 0), (-1, 0), TEXT_MUTED),
                ("TEXTCOLOR", (0, 1), (-1, -1), TEXT_WHITE),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("GRID", (0, 0), (-1, -1), 0.5, BORDER),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    elements.append(fw_table)
    elements.append(Spacer(1, 0.35 * inch))

    elements.append(Paragraph("Methodology", heading_style))
    elements.append(Spacer(1, 0.08 * inch))
    elements.append(Paragraph(METHODOLOGY_NOTE, muted_style))

    doc.build(elements, onFirstPage=_draw_page_chrome, onLaterPages=_draw_page_chrome)
    return buffer.getvalue()
