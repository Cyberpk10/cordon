"""DB-touching glue between the four signal sources (email Case creation, simulation
clicks, and event-batch ingestion) and app.threat_level.aggregation's pure scoring — mirrors
app.api.routes.events's _load_baseline_snapshot/_persist_baseline load->compute->persist
shape exactly, just for ActorThreatLevel instead of ActorBaseline.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy.orm import Session

from app.baselines.aggregation import BaselineSnapshot, WeakSignalContribution, is_known_location
from app.core.config import settings
from app.core.time import to_naive_utc
from app.db.models import ActorThreatLevel, Case
from app.events.schema import ActivityEvent
from app.models.schemas import Finding
from app.threat_level.aggregation import (
    STAGE_ACCESS,
    STAGE_BY_WEAK_CATEGORY,
    STAGE_COLLECTION,
    STAGE_DELIVERY,
    STAGE_EXFILTRATION,
    Signal,
    project_threat_level,
    record_score_snapshot,
)


def _now() -> datetime:
    return to_naive_utc(datetime.now(timezone.utc))


def _apply_signals(db: Session, account_id: UUID, actor: str, signals: list[Signal], now: datetime) -> None:
    if not signals:
        return

    row = (
        db.query(ActorThreatLevel)
        .filter(ActorThreatLevel.account_id == account_id, ActorThreatLevel.actor == actor)
        .first()
    )
    existing_score = row.current_score if row is not None else 0.0
    last_updated = to_naive_utc(row.last_updated) if row is not None and row.last_updated is not None else None
    recent_signals = list(row.recent_signals) if row is not None else []
    score_history = dict(row.score_history) if row is not None else {}

    new_score, updated_signals = project_threat_level(existing_score, last_updated, recent_signals, signals, now)
    updated_history = record_score_snapshot(score_history, new_score, now)

    if row is None:
        db.add(
            ActorThreatLevel(
                id=uuid.uuid4(),
                account_id=account_id,
                actor=actor,
                current_score=new_score,
                recent_signals=updated_signals,
                score_history=updated_history,
                last_updated=now,
            )
        )
        return

    row.current_score = new_score
    row.recent_signals = updated_signals
    row.score_history = updated_history
    # Explicit, not left to the column's onupdate=now() default: `now` here is the
    # BUSINESS-LOGIC clock (the batch's own event timestamp / case creation time), which in
    # a historical-fixture test can be far in the past relative to the real wall clock the
    # ORM default would otherwise stamp — that mismatch would silently zero out decay on the
    # next call (elapsed = max(0, fixture_now - real_wall_clock) is negative -> clamped to 0).
    row.last_updated = now


def record_case_signal(db: Session, account_id: UUID, case: Case) -> None:
    """PHISHING_EMAIL_RECEIVED — fires per recipient for any non-safe Case verdict. Called
    right after Case construction from both app.api.routes.analyze and app.api.routes.inbound
    (the only two places a real inbound/analyzed email Case gets created)."""
    if case.verdict == "safe":
        return

    points = (
        settings.threat_level_points_phishing_received_malicious
        if case.verdict == "malicious"
        else settings.threat_level_points_phishing_received_suspicious
    )
    now = _now()

    for actor in dict.fromkeys(case.to_addresses or []):  # de-dupe, preserve order
        signal = Signal(
            type="PHISHING_EMAIL_RECEIVED",
            stage=STAGE_DELIVERY,
            points=points,
            category="phishing",
            timestamp=now,
            description=f"Received a {case.verdict} email (score {case.score}/100).",
        )
        _apply_signals(db, account_id, actor, [signal], now)


def record_simulation_click(db: Session, account_id: UUID, actor_email: str) -> None:
    """SIMULATION_PHISHING_CLICKED — fires once, on the FIRST click of an authorized
    phishing-simulation link for this recipient (app.api.routes.simulation::track checks
    `recipient.clicked_at is None` before calling this, so repeat clicks don't re-fire)."""
    now = _now()
    signal = Signal(
        type="SIMULATION_PHISHING_CLICKED",
        stage=STAGE_DELIVERY,
        points=settings.threat_level_points_simulation_clicked,
        category="phishing",
        timestamp=now,
        description="Clicked a link in an authorized phishing-simulation email.",
    )
    _apply_signals(db, account_id, actor_email, [signal], now)


def _has_new_location(batch_events: list[ActivityEvent], baseline: BaselineSnapshot) -> bool:
    if baseline.event_count < settings.threat_level_min_events_for_location_check:
        return False
    for event in batch_events:
        if (
            event.action == "login"
            and event.outcome == "success"
            and event.geo is not None
            and event.geo.country
            and not is_known_location(baseline, event.geo.country)
        ):
            return True
    return False


def record_event_batch_signals(
    db: Session,
    account_id: UUID,
    actor: str,
    batch_events: list[ActivityEvent],
    baseline: BaselineSnapshot,
    weak_signal_contribution: WeakSignalContribution,
    findings: list[Finding],
    now: datetime,
) -> None:
    """Builds AUTH_ANOMALY / FIRST_TIME_SENSITIVE_ACCESS / SMALL_UNFAMILIAR_TRANSFER /
    STAGE_D_ACCUMULATOR_SIGNAL from what app.api.routes.events's per-actor loop has already
    computed this batch — no new queries. `findings` is the actor's full findings list for
    the batch (run_detections + cumulative_exfiltration + low_signal_accumulation), used only
    to detect the two named finding IDs below; every other finding is out of this stage's
    scope by design (see the Stage 1 plan's signal catalog)."""
    categories = weak_signal_contribution.categories
    finding_ids = {f.id for f in findings}
    signals: list[Signal] = []

    reasons = []
    if "auth" in categories:
        reasons.append("a handful of failed logins")
    if "hour" in categories:
        reasons.append("an atypical-hour session")
    new_location = _has_new_location(batch_events, baseline)
    if new_location:
        reasons.append("a login from a never-seen-before location")
    if reasons:
        signals.append(
            Signal(
                type="AUTH_ANOMALY",
                stage=STAGE_ACCESS,
                points=settings.threat_level_points_auth_anomaly,
                category="access",
                timestamp=now,
                description="Auth anomaly: " + ", ".join(reasons) + ".",
            )
        )

    if "sensitive" in categories:
        signals.append(
            Signal(
                type="FIRST_TIME_SENSITIVE_ACCESS",
                stage=STAGE_COLLECTION,
                points=settings.threat_level_points_sensitive_access_cold_start,
                category="sensitive",
                timestamp=now,
                description="First-time access to a sensitive resource class (cold-start baseline).",
            )
        )
    real_sensitive_finding = next((f for f in findings if f.id == "SENSITIVE_RESOURCE_FIRST_ACCESS"), None)
    if real_sensitive_finding is not None:
        signals.append(
            Signal(
                type="FIRST_TIME_SENSITIVE_ACCESS",
                stage=STAGE_COLLECTION,
                points=real_sensitive_finding.points * settings.threat_level_finding_weight,
                category="sensitive",
                timestamp=now,
                description="First-time access to a sensitive resource class.",
            )
        )

    if "transfer" in categories:
        signals.append(
            Signal(
                type="SMALL_UNFAMILIAR_TRANSFER",
                stage=STAGE_EXFILTRATION,
                points=settings.threat_level_points_small_transfer,
                category="exfiltration",
                timestamp=now,
                description="A small transfer to an unfamiliar destination.",
            )
        )

    is_accumulator_candidate = len(categories) >= 2
    accumulator_fired = "LOW_SIGNAL_PATTERN_ACCUMULATION" in finding_ids
    if is_accumulator_candidate or accumulator_fired:
        signals.append(
            Signal(
                type="STAGE_D_ACCUMULATOR_SIGNAL",
                stage=STAGE_EXFILTRATION,
                points=settings.threat_level_points_accumulator_signal,
                category="correlation",
                timestamp=now,
                description="Multiple weak signals co-occurred in the same batch (Stage D accumulator).",
            )
        )

    _apply_signals(db, account_id, actor, signals, now)
