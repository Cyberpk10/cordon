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
from app.models.schemas import (
    InvestigationRecommendedStepResponse,
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
