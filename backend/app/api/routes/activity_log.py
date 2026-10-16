"""POST /api/activity-log/analyze — parses pasted raw activity-log CSV text and runs it
through the EXACT same intrusion-detection engine the early-warning sim / POST /api/events
already uses (app.api.routes.events.ingest_activity_events — same multi-pass per-actor +
cross-actor correlation, same persistence, same auto-investigation trigger). No detection
logic lives here; see app.activity_log.parser for the CSV-to-ActivityEvent mapping. Mirrors
app.api.routes.analyze's email endpoints exactly: auth required, no extra per-route rate
limit (email's /api/analyze and /api/analyze/text don't have one either — only auth-adjacent
endpoints do, see app.auth.rate_limit), input-size and row-count caps instead of a 500 on bad
input, scoped to the authenticated user's account.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.activity_log.parser import ActivityLogParseError, parse_activity_log_csv
from app.api.routes.events import ingest_activity_events
from app.auth.dependencies import get_current_user
from app.core.config import settings
from app.db.models import Investigation, User
from app.db.session import get_db
from app.events.schema import ActivityEvent
from app.models.schemas import (
    ActivityLogAnalyzeRequest,
    ActivityLogAnalyzeResponse,
    ActivityLogSummary,
    Indicator,
)

router = APIRouter(prefix="/api/activity-log", tags=["activity-log"])


def _finding_to_indicator(finding: dict) -> Indicator:
    """Finding (app.models.schemas.Finding, as the JSON dict already stored on
    Incident.findings) is explicitly documented as "the intrusion-detection analog of
    Indicator" — same id/category/title/description/severity, `points` instead of `score`,
    and event-id references instead of free-text evidence. Mapped here rather than showing
    raw event UUIDs, which would mean nothing to a reader."""
    evidence_count = len(finding.get("evidence_event_ids") or [])
    return Indicator(
        id=finding["id"],
        category=finding["category"],
        title=finding["title"],
        description=finding["description"],
        evidence=(
            [f"{evidence_count} supporting event(s) in this window."] if evidence_count else []
        ),
        severity=finding["severity"],
        score=finding["points"],
    )


def _build_summary(events: list[ActivityEvent], *, primary_actor: str | None, other_incidents: int) -> ActivityLogSummary:
    distinct_actors = sorted({e.actor for e in events})
    source_ips = sorted({e.source_ip for e in events if e.source_ip})
    return ActivityLogSummary(
        event_count=len(events),
        distinct_actor_count=len(distinct_actors),
        primary_actor=primary_actor,
        time_range_start=min(e.timestamp for e in events),
        time_range_end=max(e.timestamp for e in events),
        source_ips=source_ips,
        other_incidents_detected=other_incidents,
    )


@router.post("/analyze", response_model=ActivityLogAnalyzeResponse)
async def analyze_activity_log(
    body: ActivityLogAnalyzeRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ActivityLogAnalyzeResponse:
    if not body.raw_text.strip():
        raise HTTPException(status_code=400, detail="Pasted activity log is empty.")
    if len(body.raw_text.encode("utf-8")) > settings.max_upload_bytes:
        raise HTTPException(
            status_code=400, detail="Pasted activity log exceeds the maximum allowed size."
        )

    try:
        events = parse_activity_log_csv(body.raw_text)
    except ActivityLogParseError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    incidents = ingest_activity_events(db, current_user.account_id, events)

    if not incidents:
        # Nothing non-safe fired anywhere in the pasted log — a clean safe result for the
        # whole batch, same as a safe email: 200, not an error.
        return ActivityLogAnalyzeResponse(
            id=uuid.uuid4(),
            created_at=datetime.utcnow(),
            verdict="safe",
            score=0,
            summary=_build_summary(events, primary_actor=None, other_incidents=0),
            indicators=[],
            framework_mappings={},
            analyst_narrative=None,
            analyst_model=None,
        )

    # The UI is a single-result view, same as the email analyzer — report the highest-scoring
    # incident as THE verdict; any others this same paste produced are counted, not dropped.
    incident, _summary = max(incidents, key=lambda pair: pair[1].score)
    other_incidents = len(incidents) - 1

    investigation = (
        db.query(Investigation).filter(Investigation.incident_id == incident.id).first()
    )

    return ActivityLogAnalyzeResponse(
        id=incident.id,
        created_at=incident.created_at,
        verdict=incident.verdict,
        score=incident.score,
        summary=_build_summary(
            events, primary_actor=incident.actor, other_incidents=other_incidents
        ),
        indicators=[_finding_to_indicator(f) for f in incident.findings],
        framework_mappings=incident.framework_mappings,
        analyst_narrative=investigation.summary if investigation else None,
        analyst_model=investigation.summary_model if investigation else None,
    )
