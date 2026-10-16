"""Security & Compliance Report (M11 Stage 1) — POST /api/reports/security-compliance
(generates + stores a PDF/JSON report and returns its full content for an immediate in-app
preview), GET /api/reports/security-compliance (list), GET /api/reports/security-compliance/
{id} (re-fetch a previously generated report's full content), and GET .../{id}/download (the
stored PDF/JSON file). Requires auth; scoped to the authenticated user's account, same
pattern as app.api.routes.audit, which this extends.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy.orm import Session

from app.auth.dependencies import get_current_user
from app.core.config import settings
from app.db.models import Account, SecurityComplianceReport, User
from app.db.session import get_db
from app.models.schemas import (
    ReportExecutiveSummary,
    ReportExposureByAttackType,
    ReportFrameworkCoverage,
    ReportHumanRiskSummary,
    ReportVerdictBreakdown,
    SecurityComplianceReportDetail,
    SecurityComplianceReportListResponse,
    SecurityComplianceReportRequest,
    SecurityComplianceReportSummary,
)
from app.reports.executive_summary import generate_deterministic_summary, generate_llm_summary
from app.reports.gather import ReportMetrics, gather_report_metrics
from app.reports.report_builder import ReportContext, build_json_report, build_pdf_report
from app.storage.audit_report_store import save_report_files

router = APIRouter(prefix="/api/reports", tags=["reports"])

DEFAULT_PERIOD_DAYS = 90


def _resolve_period(date_from: datetime | None, date_to: datetime | None) -> tuple[datetime, datetime]:
    period_end = date_to or datetime.utcnow()
    period_start = date_from or (period_end - timedelta(days=DEFAULT_PERIOD_DAYS))
    return period_start, period_end


def _to_detail(
    *,
    report_id: UUID,
    created_at: datetime,
    account_name: str,
    metrics: ReportMetrics,
    summary_text: str,
    summary_source: str,
    summary_model: str | None,
) -> SecurityComplianceReportDetail:
    return SecurityComplianceReportDetail(
        id=report_id,
        created_at=created_at,
        account_name=account_name,
        period_start=metrics.period_start,
        period_end=metrics.period_end,
        executive_summary=ReportExecutiveSummary(
            text=summary_text, source=summary_source, model=summary_model
        ),
        emails_analyzed=metrics.emails_analyzed,
        verdict_breakdown=ReportVerdictBreakdown(
            malicious=metrics.verdict_breakdown.malicious,
            suspicious=metrics.verdict_breakdown.suspicious,
            safe=metrics.verdict_breakdown.safe,
        ),
        threats_detected=metrics.threats_detected,
        threats_contained=metrics.threats_contained,
        exposure_avoided_usd=metrics.exposure_avoided_usd,
        exposure_by_attack_type=[
            ReportExposureByAttackType(
                attack_type=e.attack_type,
                count=e.count,
                avg_loss_usd=e.avg_loss_usd,
                subtotal_usd=e.subtotal_usd,
            )
            for e in metrics.exposure_by_attack_type
        ],
        incidents_detected=metrics.incidents_detected,
        early_warning_alerts_raised=metrics.early_warning_alerts_raised,
        human_risk=ReportHumanRiskSummary(
            campaigns_run=metrics.human_risk.campaigns_run,
            employees_tested=metrics.human_risk.employees_tested,
            employees_clicked=metrics.human_risk.employees_clicked,
            employees_reported=metrics.human_risk.employees_reported,
            employees_flagged_for_training=metrics.human_risk.employees_flagged_for_training,
        ),
        framework_coverage=[
            ReportFrameworkCoverage(
                framework_key=r.framework_key,
                framework_name=r.framework_name,
                total_controls=r.total_controls,
                covered_controls=r.covered_controls,
                coverage_pct=r.coverage_pct,
            )
            for r in metrics.framework_coverage
        ],
        has_any_activity=metrics.has_any_activity,
    )


@router.post("/security-compliance", response_model=SecurityComplianceReportDetail)
async def generate_security_compliance_report(
    body: SecurityComplianceReportRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SecurityComplianceReportDetail:
    period_start, period_end = _resolve_period(body.date_from, body.date_to)
    account = db.get(Account, current_user.account_id)

    metrics = gather_report_metrics(db, current_user.account_id, period_start, period_end)

    # Optional AI-authored summary, gated behind the same flag as every other LLM-narrative
    # feature in this codebase — falls back to a fully deterministic, non-LLM summary built
    # from the exact same metrics whenever the flag is off, the API key is missing, the call
    # fails, or the model cites a figure Cordon never supplied (see
    # app.reports.executive_summary's module docstring for the grounding guarantee).
    llm_summary = generate_llm_summary(metrics) if settings.enable_llm_reasoning else None
    summary = llm_summary or generate_deterministic_summary(metrics)

    report_id = uuid.uuid4()
    generated_at = datetime.utcnow()
    ctx = ReportContext(
        account_name=account.name,
        period_start=period_start,
        period_end=period_end,
        generated_at=generated_at,
        metrics=metrics,
        executive_summary=summary,
    )
    pdf_bytes = build_pdf_report(ctx)
    json_bytes = build_json_report(ctx)
    pdf_path, json_path = save_report_files(report_id, pdf_bytes, json_bytes)

    row = SecurityComplianceReport(
        id=report_id,
        account_id=current_user.account_id,
        period_start=period_start,
        period_end=period_end,
        emails_analyzed=metrics.emails_analyzed,
        threats_detected=metrics.threats_detected,
        threats_contained=metrics.threats_contained,
        exposure_avoided_usd=metrics.exposure_avoided_usd,
        executive_summary=summary.text,
        executive_summary_source=summary.source,
        pdf_path=pdf_path,
        json_path=json_path,
    )
    db.add(row)
    db.commit()
    db.refresh(row)

    return _to_detail(
        report_id=row.id,
        created_at=row.created_at,
        account_name=account.name,
        metrics=metrics,
        summary_text=summary.text,
        summary_source=summary.source,
        summary_model=summary.model,
    )


@router.get("/security-compliance", response_model=SecurityComplianceReportListResponse)
async def list_security_compliance_reports(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
) -> SecurityComplianceReportListResponse:
    query = (
        db.query(SecurityComplianceReport)
        .filter(SecurityComplianceReport.account_id == current_user.account_id)
        .order_by(SecurityComplianceReport.created_at.desc())
    )
    total = query.count()
    rows = query.offset((page - 1) * page_size).limit(page_size).all()

    items = [
        SecurityComplianceReportSummary(
            id=row.id,
            created_at=row.created_at,
            period_start=row.period_start,
            period_end=row.period_end,
            emails_analyzed=row.emails_analyzed,
            threats_detected=row.threats_detected,
            threats_contained=row.threats_contained,
            exposure_avoided_usd=row.exposure_avoided_usd,
            executive_summary_source=row.executive_summary_source,
        )
        for row in rows
    ]
    return SecurityComplianceReportListResponse(items=items, total=total, page=page, page_size=page_size)


def _get_owned_report(db: Session, report_id: UUID, account_id: UUID) -> SecurityComplianceReport:
    report = db.get(SecurityComplianceReport, report_id)
    if report is None or report.account_id != account_id:
        raise HTTPException(status_code=404, detail="Report not found.")
    return report


@router.get("/security-compliance/{report_id}", response_model=SecurityComplianceReportDetail)
async def get_security_compliance_report(
    report_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SecurityComplianceReportDetail:
    """Re-fetches a previously generated report's full content for in-app viewing. Re-derives
    the detail from the account's CURRENT data for the report's stored period, rather than
    re-reading the frozen JSON file — the distinction only matters if the account's
    historical data changes after generation (it normally doesn't), and re-deriving keeps
    this endpoint consistent with generate's own response shape without a second code path
    for parsing the stored JSON back out."""
    report = _get_owned_report(db, report_id, current_user.account_id)
    account = db.get(Account, current_user.account_id)
    metrics = gather_report_metrics(db, current_user.account_id, report.period_start, report.period_end)

    return _to_detail(
        report_id=report.id,
        created_at=report.created_at,
        account_name=account.name,
        metrics=metrics,
        summary_text=report.executive_summary,
        summary_source=report.executive_summary_source,
        summary_model=settings.llm_model if report.executive_summary_source == "llm" else None,
    )


@router.get("/security-compliance/{report_id}/download")
async def download_security_compliance_report(
    report_id: UUID,
    format: str = Query(..., pattern="^(pdf|json)$"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    report = _get_owned_report(db, report_id, current_user.account_id)

    path = report.pdf_path if format == "pdf" else report.json_path
    media_type = "application/pdf" if format == "pdf" else "application/json"
    try:
        with open(path, "rb") as f:
            content = f.read()
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Report file not found on disk.") from exc

    filename = f"cordon-security-compliance-report-{report_id}.{format}"
    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
