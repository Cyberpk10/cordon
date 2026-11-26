"""Agentic investigation layer (M10 Stage 1) — POST .../investigate runs (or re-runs) an
investigation on-demand; GET .../investigation fetches the current one. Investigations also
run automatically right after a Case/Incident is persisted at Suspicious/Malicious (see
app.investigation.build.maybe_auto_investigate, called from app.api.routes.analyze/inbound/
events) — these endpoints are what the "Investigate" UI action and the frontend's
investigation panel call.

Requires auth; every query/write is scoped to the authenticated user's own account_id
(M8 Stage 2) — a case/incident belonging to another account resolves to 404.
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.auth.dependencies import get_current_user
from app.db.models import Case, Incident, Investigation, User
from app.db.session import get_db
from app.investigation.build import save_investigation
from app.orchestration.orchestrator import run_orchestration, save_orchestration
from app.models.schemas import (
    MultiAgentResponse,
    InvestigationEvidenceItem,
    InvestigationRecommendedStepResponse,
    InvestigationReport,
    InvestigationRelatedCaseResponse,
    InvestigationRelatedIncidentResponse,
    InvestigationResponse,
    InvestigationScopeResponse,
    InvestigationSenderIntelligenceResponse,
    InvestigationThreatIntelHitResponse,
    InvestigationThreatLevelResponse,
    InvestigationTimelineEntryResponse,
)
from app.models.schemas import Finding

cases_router = APIRouter(prefix="/api/cases", tags=["investigations"])
incidents_router = APIRouter(prefix="/api/incidents", tags=["investigations"])


def _to_response(investigation: Investigation) -> InvestigationResponse:
    # Built explicitly rather than a blanket model_validate(..., from_attributes=True):
    # sender_intelligence is stored as `{}` (NOT NULL JSON column) when there's no sender to
    # profile, which must map to None on the response, not to an
    # InvestigationSenderIntelligenceResponse with every required field missing.
    return InvestigationResponse(
        id=investigation.id,
        case_id=investigation.case_id,
        incident_id=investigation.incident_id,
        created_at=investigation.created_at,
        updated_at=investigation.updated_at,
        trigger=investigation.trigger,
        actor=investigation.actor,
        verdict=investigation.verdict,
        score=investigation.score,
        sender_intelligence=(
            InvestigationSenderIntelligenceResponse.model_validate(investigation.sender_intelligence)
            if investigation.sender_intelligence
            else None
        ),
        related_cases=[
            InvestigationRelatedCaseResponse.model_validate(rc) for rc in investigation.related_cases
        ],
        related_incidents=[
            InvestigationRelatedIncidentResponse.model_validate(ri)
            for ri in investigation.related_incidents
        ],
        threat_intel_hits=[
            InvestigationThreatIntelHitResponse.model_validate(hit)
            for hit in investigation.threat_intel_hits
        ],
        threat_level=(
            InvestigationThreatLevelResponse.model_validate(investigation.threat_level)
            if investigation.threat_level
            else None
        ),
        ueba_findings=[Finding.model_validate(f) for f in investigation.ueba_findings],
        timeline=[
            InvestigationTimelineEntryResponse.model_validate(entry) for entry in investigation.timeline
        ],
        scope=InvestigationScopeResponse.model_validate(investigation.scope),
        recommended_steps=[
            InvestigationRecommendedStepResponse.model_validate(step)
            for step in investigation.recommended_steps
        ],
        summary=investigation.summary,
        summary_model=investigation.summary_model,
        summary_evidence_strength=investigation.summary_evidence_strength,
        report=InvestigationReport.model_validate(investigation.report) if investigation.report else None,
        evidence=[InvestigationEvidenceItem.model_validate(e) for e in (investigation.evidence or [])],
        tool_trace=list(investigation.tool_trace or []),
        engine=investigation.engine,
    )


@cases_router.post("/{case_id}/investigate", response_model=InvestigationResponse)
async def investigate_case(
    case_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> InvestigationResponse:
    """Runs (or re-runs) an investigation for this case on-demand, regardless of verdict —
    the auto-trigger's Suspicious/Malicious gate only applies to the automatic path."""
    case = db.get(Case, case_id)
    if case is None or case.account_id != current_user.account_id:
        raise HTTPException(status_code=404, detail="Case not found.")

    investigation = save_investigation(
        db, current_user.account_id, case=case, trigger="manual"
    )
    db.flush()
    save_orchestration(db, case, use_llm=True)  # D6 on the fresh report
    db.commit()
    db.refresh(investigation)
    return _to_response(investigation)


@cases_router.get("/{case_id}/investigation", response_model=InvestigationResponse)
async def get_case_investigation(
    case_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> InvestigationResponse:
    case = db.get(Case, case_id)
    if case is None or case.account_id != current_user.account_id:
        raise HTTPException(status_code=404, detail="Case not found.")

    investigation = (
        db.query(Investigation)
        .filter(Investigation.account_id == current_user.account_id, Investigation.case_id == case_id)
        .first()
    )
    if investigation is None:
        raise HTTPException(status_code=404, detail="No investigation has been run for this case yet.")
    return _to_response(investigation)


def _case_for(db: Session, case_id: UUID, user: User) -> Case:
    case = db.get(Case, case_id)
    if case is None or case.account_id != user.account_id:
        raise HTTPException(status_code=404, detail="Case not found.")
    return case


def _multi_agent_response(case: Case, record: dict, stored: bool) -> MultiAgentResponse:
    return MultiAgentResponse(case_id=case.id, stored=stored, **record)


@cases_router.get("/{case_id}/multi-agent", response_model=MultiAgentResponse)
async def get_case_multi_agent(
    case_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> MultiAgentResponse:
    """D6 multi-agent view. Stored record when there is one; otherwise computed now, rules-only
    (and stored when the case has an investigation to store it on)."""
    case = _case_for(db, case_id, current_user)
    investigation = (
        db.query(Investigation)
        .filter(Investigation.account_id == current_user.account_id, Investigation.case_id == case_id)
        .first()
    )
    if investigation is not None and investigation.multi_agent:
        return _multi_agent_response(case, investigation.multi_agent, True)
    if investigation is not None:
        record = save_orchestration(db, case, use_llm=False)
        db.commit()
        return _multi_agent_response(case, record, True)
    record, _ = run_orchestration(db, case, use_llm=False)
    return _multi_agent_response(case, record, False)


@cases_router.post("/{case_id}/multi-agent/run", response_model=MultiAgentResponse)
async def run_case_multi_agent(
    case_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> MultiAgentResponse:
    """Re-run the D6 synthesis now (with LLM wording when enabled; bounded by the caps)."""
    case = _case_for(db, case_id, current_user)
    record = save_orchestration(db, case, use_llm=True)
    if record is not None:
        db.commit()
        return _multi_agent_response(case, record, True)
    record, _ = run_orchestration(db, case, use_llm=True)
    return _multi_agent_response(case, record, False)


@incidents_router.post("/{incident_id}/investigate", response_model=InvestigationResponse)
async def investigate_incident(
    incident_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> InvestigationResponse:
    incident = db.get(Incident, incident_id)
    if incident is None or incident.account_id != current_user.account_id:
        raise HTTPException(status_code=404, detail="Incident not found.")

    investigation = save_investigation(
        db, current_user.account_id, incident=incident, trigger="manual"
    )
    db.commit()
    db.refresh(investigation)
    return _to_response(investigation)


@incidents_router.get("/{incident_id}/investigation", response_model=InvestigationResponse)
async def get_incident_investigation(
    incident_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> InvestigationResponse:
    incident = db.get(Incident, incident_id)
    if incident is None or incident.account_id != current_user.account_id:
        raise HTTPException(status_code=404, detail="Incident not found.")

    investigation = (
        db.query(Investigation)
        .filter(
            Investigation.account_id == current_user.account_id,
            Investigation.incident_id == incident_id,
        )
        .first()
    )
    if investigation is None:
        raise HTTPException(
            status_code=404, detail="No investigation has been run for this incident yet."
        )
    return _to_response(investigation)
