"""POST /api/events — source-agnostic ingestion of normalized activity events, with
synchronous per-actor detection (M5 Stage 1) against the actor's own behavioral baseline
(M5 Stage 2 — UEBA). Defensive monitoring only: this endpoint persists events and, when
warranted, an incident case — nothing here blocks, isolates, or otherwise alters any
external system. An incident is only created when the fused verdict for an actor's event
window is non-safe (see app.detections/app.scoring.intrusion_risk_engine) — events are
continuous telemetry, so persisting a "safe" incident per actor per batch would flood the
incidents table with routine activity. Requires auth; every event/baseline/incident is
scoped to the authenticated user's account (M8 Stage 2) — two accounts with an
identically-named actor never share a baseline or a detection window.
"""

from __future__ import annotations

import uuid
from datetime import timedelta
from uuid import UUID

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.auth.dependencies import get_current_user
from app.baselines.aggregation import BaselineSnapshot, empty_baseline, update_baseline
from app.core.config import settings
from app.core.time import to_naive_utc
from app.db.models import ActorBaseline, Event, Incident, User
from app.db.session import get_db
from app.detections import cumulative_exfiltration
from app.detections.base import ActorEventWindow
from app.detections.cross_actor import (
    ActorOutcome,
    detect_coordinated_campaign,
    detect_password_spray,
)
from app.detections.engine import run_detections
from app.events.schema import ActivityEvent, EventBatchRequest
from app.mapping.framework_mapper import map_indicators
from app.models.schemas import EventBatchResponse, Finding, IncidentSummary, Verdict
from app.scoring.intrusion_risk_engine import fuse

_CUMULATIVE_ACTIONS = frozenset({"data_transfer", "file_download"})

router = APIRouter(prefix="/api/events", tags=["events"])


def _persist_event(db: Session, account_id: UUID, event: ActivityEvent) -> Event:
    row = Event(
        id=event.id or uuid.uuid4(),
        account_id=account_id,
        # Client-supplied timestamps may or may not carry a UTC offset (both are valid
        # ISO8601). Normalizing to naive UTC here — same convention as every other
        # DB-persisted timestamp in this app (see app.core.time) — means a row just added
        # to this session never disagrees in awareness with a same-actor row loaded fresh
        # from the DB moments later in _to_activity_event below, regardless of dialect or
        # what format the caller sent. Without this, run_detections' own timestamp
        # comparisons (e.g. app.detections.impossible_travel's sort) can raise
        # "can't compare offset-naive and offset-aware datetimes".
        timestamp=to_naive_utc(event.timestamp),
        actor=event.actor,
        source_ip=event.source_ip,
        geo=event.geo.model_dump(mode="json") if event.geo else None,
        action=event.action.value,
        target=event.target,
        bytes=event.bytes,
        device=event.device,
        outcome=event.outcome,
        raw=event.raw,
    )
    db.add(row)
    return row


def _to_activity_event(row: Event) -> ActivityEvent:
    return ActivityEvent(
        id=row.id,
        # Postgres (production) returns an aware datetime for a DateTime(timezone=True)
        # column; SQLite (tests/dev) returns naive. See the identical normalization +
        # comment in _persist_event above.
        timestamp=to_naive_utc(row.timestamp),
        actor=row.actor,
        source_ip=row.source_ip,
        geo=row.geo,
        action=row.action,
        target=row.target,
        bytes=row.bytes,
        device=row.device,
        outcome=row.outcome,
        raw=row.raw,
    )


def _incident_title(actor: str, findings: list[Finding]) -> str:
    # Findings are already in deterministic order (app.detections.engine's fixed _RULES
    # order) — the first is treated as the "primary" detection for the incident title.
    return f"{findings[0].title} — {actor}"


def _query_actor_window(
    db: Session, account_id: UUID, actor: str, start, end
) -> list[Event]:
    return (
        db.query(Event)
        .filter(
            Event.account_id == account_id,
            Event.actor == actor,
            Event.timestamp >= start,
            Event.timestamp <= end,
        )
        .order_by(Event.timestamp)
        .all()
    )


def _persist_incident(
    db: Session,
    account_id: UUID,
    *,
    title: str,
    actor: str,
    findings: list[Finding],
    score: int,
    verdict: Verdict,
    window_start,
    window_end,
    related_actors: list[str] | None = None,
) -> Incident:
    framework_mappings = map_indicators(sorted({f.id for f in findings}))

    incident = Incident(
        id=uuid.uuid4(),
        account_id=account_id,
        title=title,
        actor=actor,
        verdict=verdict.value,
        score=score,
        detection_types=sorted({f.id for f in findings}),
        findings=[f.model_dump(mode="json") for f in findings],
        framework_mappings={
            key: [ref.model_dump(mode="json") for ref in refs]
            for key, refs in framework_mappings.items()
        },
        window_start=window_start,
        window_end=window_end,
        related_actors=related_actors,
    )
    db.add(incident)
    db.flush()
    db.refresh(incident)

    evidence_ids = {eid for f in findings for eid in f.evidence_event_ids}
    if evidence_ids:
        db.query(Event).filter(
            Event.account_id == account_id, Event.id.in_(evidence_ids)
        ).update({"incident_id": incident.id}, synchronize_session=False)

    return incident


def _to_summary(
    incident: Incident, score: int, verdict: Verdict, window_start, window_end
) -> IncidentSummary:
    return IncidentSummary(
        id=incident.id,
        created_at=incident.created_at,
        title=incident.title,
        actor=incident.actor,
        verdict=verdict,
        score=score,
        detection_types=incident.detection_types,
        window_start=window_start,
        window_end=window_end,
        related_actors=incident.related_actors,
    )


def _load_baseline_snapshot(db: Session, account_id: UUID, actor: str) -> BaselineSnapshot:
    row = (
        db.query(ActorBaseline)
        .filter(ActorBaseline.account_id == account_id, ActorBaseline.actor == actor)
        .first()
    )
    if row is None:
        return empty_baseline(actor)
    return BaselineSnapshot(
        actor=actor,
        hour_counts=list(row.hour_counts),
        location_counts=dict(row.location_counts),
        ip_counts=dict(row.ip_counts),
        daily_volume=dict(row.daily_volume),
        event_count=row.event_count,
    )


def _persist_baseline(db: Session, account_id: UUID, snapshot: BaselineSnapshot) -> None:
    row = (
        db.query(ActorBaseline)
        .filter(ActorBaseline.account_id == account_id, ActorBaseline.actor == snapshot.actor)
        .first()
    )
    if row is None:
        db.add(
            ActorBaseline(
                id=uuid.uuid4(),
                account_id=account_id,
                actor=snapshot.actor,
                hour_counts=snapshot.hour_counts,
                location_counts=snapshot.location_counts,
                ip_counts=snapshot.ip_counts,
                daily_volume=snapshot.daily_volume,
                event_count=snapshot.event_count,
            )
        )
        return

    row.hour_counts = snapshot.hour_counts
    row.location_counts = snapshot.location_counts
    row.ip_counts = snapshot.ip_counts
    row.daily_volume = snapshot.daily_volume
    row.event_count = snapshot.event_count


@router.post("", response_model=EventBatchResponse)
async def ingest_events(
    body: EventBatchRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> EventBatchResponse:
    account_id = current_user.account_id
    persisted_rows = [_persist_event(db, account_id, event) for event in body.events]
    db.flush()

    actors = sorted({row.actor for row in persisted_rows})
    lookback = timedelta(hours=settings.intrusion_lookback_hours)

    # ---- Pass 1: existing per-actor engine (+ new cumulative-exfiltration check), but
    # incident creation is DEFERRED — collect an ActorOutcome per actor so Pass 2 can see
    # every actor's result before any incident is persisted (needed to merge correlated
    # actors into one incident instead of N).
    outcomes: dict[str, ActorOutcome] = {}
    per_actor_context: dict[str, dict] = {}

    for actor in actors:
        actor_batch_rows = [row for row in persisted_rows if row.actor == actor]
        window_end = max(row.timestamp for row in actor_batch_rows)
        window_start = window_end - lookback

        window_rows = _query_actor_window(db, account_id, actor, window_start, window_end)
        window = ActorEventWindow(
            actor=actor, events=[_to_activity_event(row) for row in window_rows]
        )

        # Load the baseline BEFORE detection and update it AFTER — never the other way
        # around. Folding this batch in first would let a burst of malicious activity
        # inflate its own "normal" and mask itself from the very comparison meant to
        # catch it. The baseline still updates even when nothing fires: routine activity
        # is exactly what should be learned as normal.
        baseline = _load_baseline_snapshot(db, account_id, actor)
        findings = run_detections(window, baseline)

        # Cumulative exfiltration needs a much wider window than the standard 24h lookback
        # (see app.core.config.exfil_cumulative_window_days), so it can't live in the
        # _RULES registry above — query separately, only when this batch is even relevant
        # (cheap short-circuit: if it didn't add a transfer/download, the actor's
        # cumulative total didn't change since it was last evaluated).
        if any(row.action in _CUMULATIVE_ACTIONS for row in actor_batch_rows):
            wide_start = window_end - timedelta(days=settings.exfil_cumulative_window_days)
            wide_rows = _query_actor_window(db, account_id, actor, wide_start, window_end)
            wide_window = ActorEventWindow(
                actor=actor, events=[_to_activity_event(row) for row in wide_rows]
            )
            findings = findings + cumulative_exfiltration.evaluate(wide_window, baseline)

        score, verdict = fuse(findings)

        batch_events = [_to_activity_event(row) for row in actor_batch_rows]
        _persist_baseline(db, account_id, update_baseline(baseline, batch_events))

        # suspicious_source_ips: only from events actually cited as evidence by this
        # actor's own findings — feeds the coordinated-campaign correlation below, and
        # deliberately excludes incidental/benign traffic (see ActorOutcome's docstring).
        evidence_ids = {eid for f in findings for eid in f.evidence_event_ids}
        events_by_id = {e.id: e for e in window.events}
        suspicious_ips = sorted(
            {
                events_by_id[eid].source_ip
                for eid in evidence_ids
                if eid in events_by_id and events_by_id[eid].source_ip
            }
        )

        outcomes[actor] = ActorOutcome(
            actor=actor,
            verdict_is_safe=(verdict == Verdict.SAFE),
            findings=findings,
            suspicious_source_ips=suspicious_ips,
            window_start=window_start,
            window_end=window_end,
        )
        per_actor_context[actor] = {
            "score": score,
            "verdict": verdict,
            "window_start": window_start,
            "window_end": window_end,
        }

    # ---- Pass 2: coordinated-campaign correlation, scoped to this batch's actors only
    # (Stage 1 boundary — cross-batch correlation would need a background reconciliation
    # job). Actors absorbed into a qualifying group get ONE merged incident instead of
    # their own individual one; every other actor's behavior is completely unchanged.
    groups = detect_coordinated_campaign(list(outcomes.values()))
    merged_actors: set[str] = {a for g in groups for a in g.actors}

    incidents_created: list[IncidentSummary] = []

    for actor in actors:
        if actor in merged_actors:
            continue
        outcome = outcomes[actor]
        if outcome.verdict_is_safe:
            continue
        ctx = per_actor_context[actor]
        incident = _persist_incident(
            db,
            account_id,
            title=_incident_title(actor, outcome.findings),
            actor=actor,
            findings=outcome.findings,
            score=ctx["score"],
            verdict=ctx["verdict"],
            window_start=ctx["window_start"],
            window_end=ctx["window_end"],
        )
        incidents_created.append(
            _to_summary(incident, ctx["score"], ctx["verdict"], ctx["window_start"], ctx["window_end"])
        )

    for group in groups:
        union_findings = [group.finding] + [
            f.model_copy(update={"actor": a}) for a in group.actors for f in outcomes[a].findings
        ]
        score, verdict = fuse(union_findings)
        incident = _persist_incident(
            db,
            account_id,
            title=f"{group.finding.title} — {len(group.actors)} accounts",
            actor=f"{len(group.actors)} accounts (coordinated attack)",
            findings=union_findings,
            score=score,
            verdict=verdict,
            window_start=group.window_start,
            window_end=group.window_end,
            related_actors=group.actors,
        )
        incidents_created.append(
            _to_summary(incident, score, verdict, group.window_start, group.window_end)
        )

    # ---- Pass 3: cross-actor password spray. Re-queries the whole account's auth_fail
    # events over the standard lookback window (not batch-only — splitting a spray across
    # many small batches must not evade it, same reasoning as the per-actor re-query
    # above), excluding any actor who already got an incident in passes 1-2.
    already_incidented = merged_actors | {
        a for a in actors if a not in merged_actors and not outcomes[a].verdict_is_safe
    }
    batch_auth_fail_rows = [row for row in persisted_rows if row.action == "auth_fail"]
    if batch_auth_fail_rows:
        outer_end = max(row.timestamp for row in batch_auth_fail_rows)
        outer_start = outer_end - lookback
        auth_fail_rows = (
            db.query(Event)
            .filter(
                Event.account_id == account_id,
                Event.action == "auth_fail",
                Event.timestamp >= outer_start,
                Event.timestamp <= outer_end,
            )
            .order_by(Event.timestamp)
            .all()
        )
        # Excludes events already linked to an incident (from this pass or an earlier
        # request) in addition to already_incidented actors — Pass 3 deliberately re-scans
        # the whole account's auth_fail history every request (so a spray split across many
        # small batches isn't missed), which means the SAME still-in-window evidence would
        # otherwise be re-detected and raise a duplicate incident on every later, unrelated
        # request that merely happens to touch any auth_fail event within the lookback
        # window. Once an event is cited as evidence for an incident, it never is again.
        candidate_events = [
            _to_activity_event(row)
            for row in auth_fail_rows
            if row.actor not in already_incidented and row.incident_id is None
        ]
        for spray in detect_password_spray(candidate_events):
            score, verdict = fuse([spray.finding])
            incident = _persist_incident(
                db,
                account_id,
                title=f"{spray.finding.title} — {len(spray.actors)} accounts",
                actor=f"{len(spray.actors)} accounts (password spray)",
                findings=[spray.finding],
                score=score,
                verdict=verdict,
                window_start=spray.window_start,
                window_end=spray.window_end,
                related_actors=spray.actors,
            )
            incidents_created.append(
                _to_summary(incident, score, verdict, spray.window_start, spray.window_end)
            )

    db.commit()

    return EventBatchResponse(accepted=len(persisted_rows), incidents_created=incidents_created)
