"""GET /api/early-warnings, POST /api/early-warnings/{id}/ack — early-warning sensor Stage
2. An early-warning alert is raised (app.early_warning.hooks.evaluate_actors, called from
the same four places Stage 1's signal hooks are) when an actor's ActorThreatLevel crosses
into the "attack_forming" band — multiple CORROBORATING precursor signals at different
kill-chain stages, never a single signal. This is reporting + acknowledgement only: nothing
here executes any action, auto-fires anything, or blocks/isolates/resets anything — the
recommended_actions on each alert are descriptive text only (app.early_warning.playbook).
Requires auth; scoped to the authenticated user's account (M8 Stage 2).
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.auth.audit_log import log_event
from app.auth.dependencies import get_current_user
from app.core.time import to_naive_utc
from app.db.models import EarlyWarningAlert, User
from app.db.session import get_db
from app.early_warning.hooks import build_timeline_summary, has_active_incident
from app.mapping.framework_mapper import map_indicators
from app.models.schemas import (
    EarlyWarningActionResponse,
    EarlyWarningAlertResponse,
    EarlyWarningListResponse,
    ThreatLevelSignalResponse,
)
from app.threat_level.aggregation import compute_band

router = APIRouter(prefix="/api/early-warnings", tags=["early-warnings"])


def _client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def _to_response(row: EarlyWarningAlert, db: Session, account_id: UUID, now: datetime) -> EarlyWarningAlertResponse:
    band = compute_band(row.score, row.signal_timeline)
    if has_active_incident(db, account_id, row.actor, now):
        band = "active_incident"

    return EarlyWarningAlertResponse(
        id=row.id,
        actor=row.actor,
        band=band,
        score=round(row.score, 1),
        created_at=row.created_at,
        signal_timeline=[ThreatLevelSignalResponse(**s) for s in row.signal_timeline],
        timeline_summary=build_timeline_summary(row.signal_timeline),
        recommended_actions=[EarlyWarningActionResponse(**a) for a in row.recommended_actions],
        framework_mappings=map_indicators(["EARLY_WARNING_ATTACK_FORMING"]),
    )


@router.get("", response_model=EarlyWarningListResponse)
async def get_early_warnings(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> EarlyWarningListResponse:
    now = to_naive_utc(datetime.now(timezone.utc))
    rows = (
        db.query(EarlyWarningAlert)
        .filter(EarlyWarningAlert.account_id == current_user.account_id, EarlyWarningAlert.status == "active")
        .order_by(EarlyWarningAlert.score.desc())
        .all()
    )
    return EarlyWarningListResponse(
        alerts=[_to_response(row, db, current_user.account_id, now) for row in rows]
    )


@router.post("/{alert_id}/ack", response_model=EarlyWarningAlertResponse)
async def acknowledge_early_warning(
    alert_id: UUID,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> EarlyWarningAlertResponse:
    row = (
        db.query(EarlyWarningAlert)
        .filter(EarlyWarningAlert.id == alert_id, EarlyWarningAlert.account_id == current_user.account_id)
        .first()
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Early-warning alert not found")

    now = to_naive_utc(datetime.now(timezone.utc))
    if row.status != "acknowledged":
        row.status = "acknowledged"
        row.acknowledged_at = now
        row.acknowledged_by = current_user.email
        log_event(
            db,
            event_type="early_warning_acknowledged",
            account_id=current_user.account_id,
            user_id=current_user.id,
            detail={"alert_id": str(row.id), "actor": row.actor},
            ip_address=_client_ip(request),
        )

    db.commit()
    db.refresh(row)
    return _to_response(row, db, current_user.account_id, now)
