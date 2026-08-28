"""Audit Mode — GET /api/audit/evidence (live per-control evidence preview) and
POST /api/audit/report (generates + stores a timestamped PDF/JSON evidence pack), plus
GET /api/audit/reports (list) and GET /api/audit/reports/{id}/download (re-serve the
stored files) so generated packs are listable and reproducible. Requires auth; scoped to
the authenticated user's account (M8 Stage 2).
"""

from __future__ import annotations

import dataclasses
import uuid
from datetime import datetime, timedelta
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy.orm import Session

from app.audit.aggregation import ControlEvidence, evidence_for_framework
from app.audit.report_builder import ReportContext, build_json_report, build_pdf_report
from app.auth.dependencies import get_current_user
from app.dashboard.aggregation import CaseRow
from app.db.models import (
    AuditReport,
    Case,
    SimulationCampaign,
    SimulationRecipient,
    SimulationTrainingRecommendation,
    User,
)
from app.db.session import get_db
from app.human_risk.audit_evidence import (
    SimulationCampaignRow,
    SimulationRecipientRow,
    human_risk_evidence_for_framework,
)
from app.human_risk.framework_mapping import HUMAN_RISK_CONTROL_IDS
from app.mapping.framework_mapper import (
    LoadedFramework,
    framework_display_names,
    get_framework,
    resolve_framework_alias,
)
from app.models.schemas import (
    AuditCaseRef,
    AuditControlEvidence,
    AuditEvidenceResponse,
    AuditFramework,
    AuditReportListResponse,
    AuditReportRequest,
    AuditReportSummary,
    HumanRiskEvidenceResponse,
)
from app.storage.audit_report_store import save_report_files

router = APIRouter(prefix="/api/audit", tags=["audit"])

DEFAULT_PERIOD_DAYS = 30


def _resolve_period(date_from: datetime | None, date_to: datetime | None) -> tuple[datetime, datetime]:
    period_end = date_to or datetime.utcnow()
    period_start = date_from or (period_end - timedelta(days=DEFAULT_PERIOD_DAYS))
    return period_start, period_end


def _to_case_row(case: Case) -> CaseRow:
    return CaseRow(
        id=str(case.id),
        created_at=case.created_at,
        verdict=case.verdict,
        indicators=case.indicators,
        framework_mappings=case.framework_mappings,
    )


def _load_framework_or_404(alias: AuditFramework) -> tuple[str, LoadedFramework]:
    framework_key = resolve_framework_alias(alias)
    framework = get_framework(framework_key)
    if framework is None:
        raise HTTPException(status_code=404, detail=f"Framework '{alias.value}' is not loaded.")
    return framework_key, framework


def _cases_in_period(
    db: Session, account_id: UUID, period_start: datetime, period_end: datetime
) -> list[CaseRow]:
    cases_orm = (
        db.query(Case)
        .filter(
            Case.account_id == account_id,
            Case.created_at >= period_start,
            Case.created_at <= period_end,
        )
        .all()
    )
    return [_to_case_row(c) for c in cases_orm]


def _merge_human_risk_evidence(
    db: Session,
    account_id: UUID,
    framework_key: str,
    period_start: datetime,
    period_end: datetime,
    evidence: list[ControlEvidence],
) -> list[ControlEvidence]:
    """Attaches human-risk (phishing-simulation) evidence to the small, fixed set of
    controls in HUMAN_RISK_CONTROL_IDS[framework_key] — a parallel, additive evidence
    source alongside case-based detections (see app.human_risk.audit_evidence's module
    docstring for why a simulation campaign isn't folded into evidence_for_framework
    itself). No-op (returns `evidence` unchanged) for any framework with no mapped
    controls."""
    control_ids = HUMAN_RISK_CONTROL_IDS.get(framework_key)
    if not control_ids:
        return evidence

    campaigns_orm = (
        db.query(SimulationCampaign)
        .filter(
            SimulationCampaign.account_id == account_id,
            SimulationCampaign.sent_at.isnot(None),
            SimulationCampaign.sent_at >= period_start,
            SimulationCampaign.sent_at <= period_end,
        )
        .all()
    )
    campaign_ids = [c.id for c in campaigns_orm]
    recipients_orm = (
        db.query(SimulationRecipient).filter(SimulationRecipient.campaign_id.in_(campaign_ids)).all()
        if campaign_ids
        else []
    )
    trained_emails = {
        row[0]
        for row in db.query(SimulationTrainingRecommendation.recipient).filter(
            SimulationTrainingRecommendation.account_id == account_id,
            SimulationTrainingRecommendation.updated_at >= period_start,
            SimulationTrainingRecommendation.updated_at <= period_end,
        )
    }

    hr_evidence = human_risk_evidence_for_framework(
        campaigns=[
            SimulationCampaignRow(id=str(c.id), sent_at=c.sent_at, template_id=c.template_id)
            for c in campaigns_orm
        ],
        recipients=[
            SimulationRecipientRow(
                campaign_id=str(r.campaign_id),
                email=r.email,
                clicked_at=r.clicked_at,
                submitted_at=r.submitted_at,
                reported_at=r.reported_at,
            )
            for r in recipients_orm
        ],
        trained_recipient_emails=trained_emails,
    )

    return [
        dataclasses.replace(
            e, human_risk=hr_evidence, operating=e.operating or hr_evidence.campaigns_run > 0
        )
        if e.control_id in control_ids
        else e
        for e in evidence
    ]


def _to_audit_control_evidence(e: ControlEvidence) -> AuditControlEvidence:
    return AuditControlEvidence(
        control_id=e.control_id,
        control_name=e.control_name,
        detection_count=e.detection_count,
        operating=e.operating,
        sample_cases=[
            AuditCaseRef(id=s.id, verdict=s.verdict, created_at=s.created_at) for s in e.sample_cases
        ],
        human_risk_evidence=(
            HumanRiskEvidenceResponse(
                campaigns_run=e.human_risk.campaigns_run,
                distinct_employees_tested=e.human_risk.distinct_employees_tested,
                distinct_employees_trained=e.human_risk.distinct_employees_trained,
                sample_campaign_ids=[UUID(cid) for cid in e.human_risk.sample_campaign_ids],
            )
            if e.human_risk
            else None
        ),
    )


@router.get("/evidence", response_model=AuditEvidenceResponse)
async def get_audit_evidence(
    framework: AuditFramework,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    date_from: datetime | None = None,
    date_to: datetime | None = None,
) -> AuditEvidenceResponse:
    framework_key, loaded = _load_framework_or_404(framework)
    period_start, period_end = _resolve_period(date_from, date_to)
    cases = _cases_in_period(db, current_user.account_id, period_start, period_end)

    evidence = evidence_for_framework(cases, loaded.controls_by_id, framework_key)
    evidence = _merge_human_risk_evidence(
        db, current_user.account_id, framework_key, period_start, period_end, evidence
    )

    return AuditEvidenceResponse(
        framework_key=framework_key,
        framework_name=loaded.name,
        period_start=period_start,
        period_end=period_end,
        controls=[_to_audit_control_evidence(e) for e in evidence],
        total_controls=len(evidence),
        operating_controls=sum(1 for e in evidence if e.operating),
    )


@router.post("/report", response_model=AuditReportSummary)
async def generate_audit_report(
    body: AuditReportRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AuditReportSummary:
    framework_key, loaded = _load_framework_or_404(body.framework)
    period_start, period_end = _resolve_period(body.date_from, body.date_to)
    cases = _cases_in_period(db, current_user.account_id, period_start, period_end)

    evidence = evidence_for_framework(cases, loaded.controls_by_id, framework_key)
    evidence = _merge_human_risk_evidence(
        db, current_user.account_id, framework_key, period_start, period_end, evidence
    )
    operating_controls = sum(1 for e in evidence if e.operating)
    total_supporting_cases = len({cid for e in evidence for cid in e.supporting_case_ids})

    report_id = uuid.uuid4()
    generated_at = datetime.utcnow()
    ctx = ReportContext(
        framework_key=framework_key,
        framework_name=loaded.name,
        framework_version=loaded.version,
        period_start=period_start,
        period_end=period_end,
        generated_at=generated_at,
        controls=evidence,
        total_controls=len(evidence),
        operating_controls=operating_controls,
        total_supporting_cases=total_supporting_cases,
    )

    json_bytes = build_json_report(ctx)
    pdf_bytes = build_pdf_report(ctx)
    pdf_path, json_path = save_report_files(report_id, pdf_bytes, json_bytes)

    report = AuditReport(
        id=report_id,
        account_id=current_user.account_id,
        framework_key=framework_key,
        period_start=period_start,
        period_end=period_end,
        total_controls=len(evidence),
        operating_controls=operating_controls,
        total_supporting_cases=total_supporting_cases,
        pdf_path=pdf_path,
        json_path=json_path,
    )
    db.add(report)
    db.commit()
    db.refresh(report)

    return AuditReportSummary(
        id=report.id,
        created_at=report.created_at,
        framework_key=report.framework_key,
        framework_name=loaded.name,
        period_start=report.period_start,
        period_end=report.period_end,
        total_controls=report.total_controls,
        operating_controls=report.operating_controls,
        total_supporting_cases=report.total_supporting_cases,
    )


@router.get("/reports", response_model=AuditReportListResponse)
async def list_audit_reports(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
) -> AuditReportListResponse:
    query = (
        db.query(AuditReport)
        .filter(AuditReport.account_id == current_user.account_id)
        .order_by(AuditReport.created_at.desc())
    )
    total = query.count()
    rows = query.offset((page - 1) * page_size).limit(page_size).all()

    names = framework_display_names()
    items = [
        AuditReportSummary(
            id=row.id,
            created_at=row.created_at,
            framework_key=row.framework_key,
            framework_name=names.get(row.framework_key, row.framework_key),
            period_start=row.period_start,
            period_end=row.period_end,
            total_controls=row.total_controls,
            operating_controls=row.operating_controls,
            total_supporting_cases=row.total_supporting_cases,
        )
        for row in rows
    ]

    return AuditReportListResponse(items=items, total=total, page=page, page_size=page_size)


@router.get("/reports/{report_id}/download")
async def download_audit_report(
    report_id: UUID,
    format: str = Query(..., pattern="^(pdf|json)$"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    report = db.get(AuditReport, report_id)
    if report is None or report.account_id != current_user.account_id:
        raise HTTPException(status_code=404, detail="Report not found.")

    path = report.pdf_path if format == "pdf" else report.json_path
    media_type = "application/pdf" if format == "pdf" else "application/json"
    try:
        with open(path, "rb") as f:
            content = f.read()
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Report file not found on disk.") from exc

    filename = f"cordon-audit-{report.framework_key}-{report_id}.{format}"
    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
