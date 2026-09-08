"""DB-touching glue for early-warning sensor Stage 2 — evaluates an actor's just-updated
ActorThreatLevel (Stage 1) against app.threat_level.aggregation.compute_band's corroboration
gate, and upserts a persisted EarlyWarningAlert when they cross into "attack_forming".
Mirrors app.threat_level.hooks's load->compute->persist shape.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from uuid import UUID

from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.time import to_naive_utc
from app.db.models import ActorThreatLevel, EarlyWarningAlert, Incident
from app.early_warning.playbook import generate_early_warning_playbook
from app.threat_level.aggregation import compute_band


def has_active_incident(db: Session, account_id: UUID, actor: str, now: datetime) -> bool:
    """True if a real Incident names this actor (directly, or as part of a merged
    cross-actor incident's related_actors) within early_warning_incident_lookback_days.
    Filtered in Python after a bounded query — related_actors is a plain JSON list, and this
    keeps the check portable across SQLite (tests) and Postgres (prod) without a
    dialect-specific JSON-containment query."""
    cutoff = now - timedelta(days=settings.early_warning_incident_lookback_days)
    rows = (
        db.query(Incident)
        .filter(Incident.account_id == account_id, Incident.created_at >= cutoff)
        .all()
    )
    for row in rows:
        if row.actor == actor:
            return True
        if row.related_actors and actor in row.related_actors:
            return True
    return False


def build_timeline_summary(signals: list[dict]) -> str:
    """'{description} ({date}) -> {description} ({date}) -> ...', oldest first — the
    human-readable reasoning timeline (e.g. "phish clicked Mon -> new-location login Wed ->
    first finance-file access Thu")."""
    ordered = sorted(signals, key=lambda s: s["timestamp"])
    parts = []
    for signal in ordered:
        date_str = datetime.fromisoformat(signal["timestamp"]).strftime("%a %b %d")
        parts.append(f"{signal['description']} ({date_str})")
    return " -> ".join(parts)


def evaluate_actors(db: Session, account_id: UUID, actors: list[str], now: datetime) -> None:
    """Called right after a Stage 1 record_* hook for the same actor(s) in the same
    request. Needs db.flush() first: the session (app.db.session.SessionLocal) is
    autoflush=False, so the ActorThreatLevel row Stage 1 just added/mutated wouldn't
    otherwise be visible to the query below within the same transaction."""
    db.flush()

    for actor in dict.fromkeys(actors):  # de-dupe, preserve order
        row = (
            db.query(ActorThreatLevel)
            .filter(ActorThreatLevel.account_id == account_id, ActorThreatLevel.actor == actor)
            .first()
        )
        if row is None:
            continue

        band = compute_band(row.current_score, row.recent_signals)
        if band != "attack_forming":
            continue

        signal_timeline = sorted(row.recent_signals, key=lambda s: s["timestamp"])
        signal_types = [s["type"] for s in signal_timeline]
        recommended_actions = [
            {
                "step_id": step.step_id,
                "title": step.title,
                "description": step.description,
                "category": step.category,
            }
            for step in generate_early_warning_playbook(signal_types)
        ]

        existing = (
            db.query(EarlyWarningAlert)
            .filter(
                EarlyWarningAlert.account_id == account_id,
                EarlyWarningAlert.actor == actor,
                EarlyWarningAlert.status == "active",
            )
            .first()
        )
        if existing is not None:
            existing.score = row.current_score
            existing.signal_timeline = signal_timeline
            existing.recommended_actions = recommended_actions
            continue

        db.add(
            EarlyWarningAlert(
                id=uuid.uuid4(),
                account_id=account_id,
                actor=actor,
                status="active",
                score=row.current_score,
                signal_timeline=signal_timeline,
                recommended_actions=recommended_actions,
                created_at=to_naive_utc(now) if now.tzinfo is not None else now,
            )
        )
