"""GET/DELETE endpoints for browsing and managing persisted analysis cases, plus the
analyst-feedback POST .../label endpoint (Stage 3). Every endpoint requires auth and is
scoped to the authenticated user's account (M8 Stage 2) — deleting a case is admin-only."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.auth.audit_log import log_event
from app.auth.dependencies import get_current_user, require_admin
from app.db.models import Case, Label, User
from app.db.session import get_db
from app.models.schemas import (
    CaseDetailResponse,
    CaseTriageRequest,
    CaseListResponse,
    CaseSummary,
    LabelRequest,
    LabelResponse,
    Verdict,
)
from app.storage.raw_email_store import delete_raw_email

router = APIRouter(prefix="/api/cases", tags=["cases"])


def _latest_label(db: Session, account_id: UUID, case_id: UUID) -> Label | None:
    return (
        db.query(Label)
        .filter(Label.account_id == account_id, Label.case_id == case_id)
        .order_by(Label.created_at.desc())
        .first()
    )


def _to_case_detail(case: Case, latest_label: Label | None) -> CaseDetailResponse:
    return CaseDetailResponse(
        id=case.id,
        created_at=case.created_at,
        filename=case.filename,
        channel=case.channel,
        verdict=case.verdict,
        score=case.score,
        from_addr=case.from_addr,
        subject=case.subject,
        indicators=case.indicators,
        framework_mappings=case.framework_mappings,
        analyst_narrative=case.analyst_narrative,
        analyst_model=case.analyst_model,
        llm_intent_category=case.llm_intent_category,
        llm_intent_risk=case.llm_intent_risk,
        llm_intent_confidence=case.llm_intent_confidence,
        llm_intent_reasons=case.llm_intent_reasons,
        ml_probability=case.ml_probability,
        ml_model_version=case.ml_model_version,
        sender_ip_info=case.sender_ip_info,
        account_takeover=case.account_takeover,
        sender_baseline=case.sender_baseline,
        latest_label=LabelResponse.model_validate(latest_label) if latest_label else None,
        status=case.status or "new",
        priority=case.priority,
        engine_tags=list(case.engine_tags or []),
        campaign_id=case.campaign_id,
    )


@router.get("", response_model=CaseListResponse)
async def list_cases(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    verdict: Verdict | None = None,
    channel: str | None = None,
    date_from: datetime | None = None,
    date_to: datetime | None = None,
) -> CaseListResponse:
    query = db.query(Case).filter(Case.account_id == current_user.account_id)
    if verdict is not None:
        query = query.filter(Case.verdict == verdict.value)
    if channel is not None:
        query = query.filter(Case.channel == channel)
    if date_from is not None:
        query = query.filter(Case.created_at >= date_from)
    if date_to is not None:
        query = query.filter(Case.created_at <= date_to)

    total = query.count()
    rows = (
        query.order_by(Case.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    return CaseListResponse(
        items=[
            CaseSummary.model_validate(row).model_copy(
                update={"account_takeover_kind": (row.account_takeover or {}).get("kind")}
            )
            for row in rows
        ],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/{case_id}", response_model=CaseDetailResponse)
async def get_case(
    case_id: UUID, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)
) -> CaseDetailResponse:
    case = db.get(Case, case_id)
    if case is None or case.account_id != current_user.account_id:
        raise HTTPException(status_code=404, detail="Case not found.")
    return _to_case_detail(case, _latest_label(db, current_user.account_id, case_id))


@router.patch("/{case_id}/triage", response_model=CaseDetailResponse)
async def set_triage(
    case_id: UUID,
    body: CaseTriageRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> CaseDetailResponse:
    """A person sets status/priority. Always wins over the autonomy engine: a later undo of
    an engine action that set these values refuses rather than overwrite this."""
    case = db.get(Case, case_id)
    if case is None or case.account_id != current_user.account_id:
        raise HTTPException(status_code=404, detail="Case not found.")
    before = {"status": case.status, "priority": case.priority}
    if body.status is not None:
        case.status = body.status
    if body.priority is not None:
        case.priority = body.priority
    log_event(db, event_type="case_triage_updated", account_id=current_user.account_id,
              user_id=current_user.id, detail={"case_id": str(case_id), "before": before,
                                               "after": {"status": case.status, "priority": case.priority}})
    db.commit()
    db.refresh(case)
    return _to_case_detail(case, _latest_label(db, current_user.account_id, case_id))


@router.delete("/{case_id}", status_code=204)
async def delete_case(
    case_id: UUID, db: Session = Depends(get_db), current_user: User = Depends(require_admin)
) -> None:
    case = db.get(Case, case_id)
    if case is None or case.account_id != current_user.account_id:
        raise HTTPException(status_code=404, detail="Case not found.")
    log_event(
        db,
        event_type="case_deleted",
        account_id=current_user.account_id,
        user_id=current_user.id,
        detail={"case_id": str(case_id)},
    )
    db.delete(case)
    db.commit()
    delete_raw_email(case_id)


@router.post("/{case_id}/label", response_model=LabelResponse)
async def label_case(
    case_id: UUID,
    body: LabelRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> LabelResponse:
    """Record an analyst's verdict on a case. Append-only — relabeling inserts a new row
    rather than overwriting the previous one, so the full labeling history is preserved."""
    case = db.get(Case, case_id)
    if case is None or case.account_id != current_user.account_id:
        raise HTTPException(status_code=404, detail="Case not found.")

    label = Label(
        account_id=current_user.account_id,
        case_id=case_id,
        analyst_verdict=body.analyst_verdict.value,
        note=body.note,
        labeled_by=current_user.email,
    )
    db.add(label)
    db.commit()
    db.refresh(label)

    return LabelResponse.model_validate(label)
