"""GET /api/threat-level — early-warning sensor Stage 1. Reporting-only: every
ActorThreatLevel row is lazily decayed to "now" on read (the row itself only physically
advances when a new signal arrives — see app.threat_level.hooks), so a read months after the
last signal still reflects the actual current, decayed score. Requires auth; scoped to the
authenticated user's account (M8 Stage 2), same convention as every other per-account list
endpoint.
"""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.auth.dependencies import get_current_user
from app.core.time import to_naive_utc
from app.db.models import ActorThreatLevel, User
from app.db.session import get_db
from app.models.schemas import (
    ThreatLevelEntryResponse,
    ThreatLevelListResponse,
    ThreatLevelSignalResponse,
)
from app.threat_level.aggregation import compute_level, compute_trend, decay_score

router = APIRouter(prefix="/api/threat-level", tags=["threat-level"])


@router.get("", response_model=ThreatLevelListResponse)
async def get_threat_levels(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ThreatLevelListResponse:
    now = to_naive_utc(datetime.now(timezone.utc))
    rows = (
        db.query(ActorThreatLevel)
        .filter(ActorThreatLevel.account_id == current_user.account_id)
        .all()
    )

    entries: list[ThreatLevelEntryResponse] = []
    for row in rows:
        last_updated = to_naive_utc(row.last_updated) if row.last_updated is not None else None
        score = decay_score(row.current_score, last_updated, now)
        if score <= 0:
            continue

        entries.append(
            ThreatLevelEntryResponse(
                actor=row.actor,
                score=round(score, 1),
                level=compute_level(score),
                trend=compute_trend(row.score_history, score, now),
                contributing_signals=[
                    ThreatLevelSignalResponse(**signal) for signal in row.recent_signals
                ],
            )
        )

    entries.sort(key=lambda e: e.score, reverse=True)
    return ThreatLevelListResponse(actors=entries)
