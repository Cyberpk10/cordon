"""Pure aggregation math for per-actor behavioral baselines (M5 Stage 2 — UEBA; extended in
Cordon detection max-out Stage B with resource-sensitivity tracking and anti-poisoning ramp
detection) — no DB/SQLAlchemy here, same separation as app.dashboard.aggregation /
app.risk_model.aggregation. BaselineSnapshot is a DB-free read view of app.db.models.
ActorBaseline; update_baseline is the pure function that folds newly-ingested events into a
snapshot, which the route layer then persists.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass, field
from datetime import datetime

from app.baselines.resource_sensitivity import classify_resource_sensitivity
from app.core.config import settings
from app.events.schema import ActivityEvent

# Mirrors app.detections.off_hours_access._SENSITIVE_ACTIONS — kept as an independent
# constant (not imported) so app.baselines never depends on app.detections, only the
# other way around. Update both together if the sensitive-action set ever changes.
_HOUR_TRACKED_ACTIONS = frozenset(
    {
        "login",
        "file_access",
        "file_download",
        "db_query",
        "privilege_change",
        "config_change",
        "data_transfer",
    }
)
# Mirrors app.detections.mass_file_access._FILE_ACTIONS.
_VOLUME_TRACKED_ACTIONS = frozenset({"file_access", "file_download"})


@dataclass(frozen=True)
class BaselineSnapshot:
    actor: str
    hour_counts: list[int] = field(default_factory=lambda: [0] * 24)
    location_counts: dict[str, int] = field(default_factory=dict)
    ip_counts: dict[str, int] = field(default_factory=dict)
    daily_volume: dict[str, int] = field(default_factory=dict)
    event_count: int = 0
    # Stage B additions below — all additive, defaulting to empty so every pre-Stage-B
    # baseline row round-trips unchanged.
    #
    # Sensitivity CLASSES (not individual resource paths — see app.baselines.
    # resource_sensitivity's module docstring for why) this actor has ever been observed
    # accessing. A union, never trimmed — bounded by the small, fixed number of configured
    # classes (finance/hr/legal by default), unlike every trimmed/rolling field below.
    sensitive_classes_seen: frozenset[str] = field(default_factory=frozenset)
    # Per-day count of sensitive-class file accesses, trimmed to the SAME rolling window as
    # daily_volume — powers the within-window sensitive-ratio ramp check.
    daily_sensitive_count: dict[str, int] = field(default_factory=dict)
    # The anti-poisoning anchor: identical per-day bookkeeping to daily_volume/
    # daily_sensitive_count, but trimmed to a much longer window
    # (settings.baseline_long_term_window_days) instead of the recent rolling one. A ramp
    # patient enough to outlast the recent window still can't roll this history away before
    # it ages out of a window measured in months, not weeks.
    long_term_daily_volume: dict[str, int] = field(default_factory=dict)
    long_term_daily_sensitive_count: dict[str, int] = field(default_factory=dict)
    # Detection max-out Stage D additions below. suspicious_pattern_score is the persisted,
    # already-decayed-as-of-last_updated chronic score (see project_suspicious_pattern_score);
    # last_updated is carried through from ActorBaseline.last_updated purely as decay math
    # input, never recomputed here — the DB column's own onupdate is what actually advances
    # it on persist.
    suspicious_pattern_score: float = 0.0
    last_updated: datetime | None = None


@dataclass(frozen=True)
class RampResult:
    """Which anti-poisoning ramp mechanism(s) fired, plus the numbers behind each — the
    detection module (app.detections.baseline_ramp) turns this into evidence/score, this
    module never touches scoring."""

    volume_ramp_detected: bool = False
    volume_early_mean: float = 0.0
    volume_recent_mean: float = 0.0
    sensitive_ratio_ramp_detected: bool = False
    sensitive_ratio_early_mean: float = 0.0
    sensitive_ratio_recent_mean: float = 0.0
    long_term_drift_detected: bool = False
    long_term_anchor_mean: float = 0.0
    long_term_recent_mean: float = 0.0

    @property
    def any_detected(self) -> bool:
        return self.volume_ramp_detected or self.sensitive_ratio_ramp_detected or self.long_term_drift_detected


def empty_baseline(actor: str) -> BaselineSnapshot:
    """A fresh baseline for an actor with no prior history — the cold-start starting point."""
    return BaselineSnapshot(actor=actor)


def _trim_daily_volume(daily_volume: dict[str, int], window_days: int) -> dict[str, int]:
    if len(daily_volume) <= window_days:
        return dict(daily_volume)
    kept_dates = sorted(daily_volume.keys())[-window_days:]
    return {d: daily_volume[d] for d in kept_dates}


def update_baseline(existing: BaselineSnapshot, new_events: list[ActivityEvent]) -> BaselineSnapshot:
    """Pure function: folds new_events into existing, returning a new snapshot. Never
    called with events already reflected in `existing` — the caller (app.api.routes.events)
    is responsible for only passing the just-ingested batch, not the full detection window,
    to avoid double-counting."""
    hour_counts = list(existing.hour_counts)
    location_counts = dict(existing.location_counts)
    ip_counts = dict(existing.ip_counts)
    daily_volume = dict(existing.daily_volume)
    event_count = existing.event_count
    sensitive_classes_seen = set(existing.sensitive_classes_seen)
    daily_sensitive_count = dict(existing.daily_sensitive_count)
    long_term_daily_volume = dict(existing.long_term_daily_volume)
    long_term_daily_sensitive_count = dict(existing.long_term_daily_sensitive_count)

    for event in new_events:
        event_count += 1

        if event.action in _HOUR_TRACKED_ACTIONS:
            hour_counts[event.timestamp.hour] += 1

        if event.action == "login" and event.outcome == "success":
            if event.geo and event.geo.country:
                location_counts[event.geo.country] = location_counts.get(event.geo.country, 0) + 1
            if event.source_ip:
                ip_counts[event.source_ip] = ip_counts.get(event.source_ip, 0) + 1

        if event.action in _VOLUME_TRACKED_ACTIONS:
            day_key = event.timestamp.date().isoformat()
            daily_volume[day_key] = daily_volume.get(day_key, 0) + 1
            long_term_daily_volume[day_key] = long_term_daily_volume.get(day_key, 0) + 1

            sensitivity_class = classify_resource_sensitivity(event.target)
            if sensitivity_class is not None:
                sensitive_classes_seen.add(sensitivity_class)
                daily_sensitive_count[day_key] = daily_sensitive_count.get(day_key, 0) + 1
                long_term_daily_sensitive_count[day_key] = (
                    long_term_daily_sensitive_count.get(day_key, 0) + 1
                )

    daily_volume = _trim_daily_volume(daily_volume, settings.baseline_daily_volume_window_days)
    daily_sensitive_count = _trim_daily_volume(
        daily_sensitive_count, settings.baseline_daily_volume_window_days
    )
    long_term_daily_volume = _trim_daily_volume(
        long_term_daily_volume, settings.baseline_long_term_window_days
    )
    long_term_daily_sensitive_count = _trim_daily_volume(
        long_term_daily_sensitive_count, settings.baseline_long_term_window_days
    )

    return BaselineSnapshot(
        actor=existing.actor,
        hour_counts=hour_counts,
        location_counts=location_counts,
        ip_counts=ip_counts,
        daily_volume=daily_volume,
        event_count=event_count,
        sensitive_classes_seen=frozenset(sensitive_classes_seen),
        daily_sensitive_count=daily_sensitive_count,
        long_term_daily_volume=long_term_daily_volume,
        long_term_daily_sensitive_count=long_term_daily_sensitive_count,
        # Stage D's chronic score is projected/persisted separately by the route layer
        # (app.api.routes.events, via project_suspicious_pattern_score) — carried through
        # unchanged here so update_baseline stays a pure fold over new_events alone.
        suspicious_pattern_score=existing.suspicious_pattern_score,
        last_updated=existing.last_updated,
    )


def is_typical_hour(snapshot: BaselineSnapshot, hour: int) -> bool:
    return snapshot.hour_counts[hour] >= settings.baseline_min_hour_occurrences


def is_known_location(snapshot: BaselineSnapshot, country: str) -> bool:
    return snapshot.location_counts.get(country, 0) > 0


def is_volume_anomalous(snapshot: BaselineSnapshot, current_count: int) -> bool | None:
    """None means "not enough history to judge" (cold start) — callers must fall back to
    a static threshold in that case, never treat None as either true or false."""
    if len(snapshot.daily_volume) < settings.baseline_min_days_for_volume:
        return None

    values = list(snapshot.daily_volume.values())
    mean = statistics.fmean(values)
    stdev = statistics.pstdev(values) if len(values) > 1 else 0.0
    threshold = mean + settings.baseline_volume_stddev_multiplier * stdev
    return current_count > threshold


def is_sensitive_class_first_seen(snapshot: BaselineSnapshot, sensitivity_class: str) -> bool:
    return sensitivity_class not in snapshot.sensitive_classes_seen


def _split_halves(dates: list[str]) -> tuple[list[str], list[str]]:
    midpoint = len(dates) // 2
    return dates[:midpoint], dates[midpoint:]


def _majority_at_or_above(values: list[float], threshold: float) -> bool:
    if not values:
        return False
    at_or_above = sum(1 for v in values if v >= threshold)
    return at_or_above > len(values) / 2


def evaluate_ramp_anomaly(snapshot: BaselineSnapshot) -> RampResult | None:
    """Anti-poisoning ramp detection (Cordon detection max-out, Stage B) — a steady,
    multi-week increase is anomalous even when no single day ever spikes, since
    is_volume_anomalous above only ever compares TODAY against the actor's own (potentially
    already-poisoned) history, never checks whether that history itself has a trend. Returns
    None only if NONE of the three sub-checks below had enough data at all (graceful cold
    start) — any individual sub-check independently skips itself if its own data
    requirement isn't met, so a snapshot can have e.g. enough data for the within-window
    checks but not yet for the long-term anchor.
    """
    result = RampResult()
    any_checked = False

    dates = sorted(snapshot.daily_volume.keys())
    if len(dates) >= settings.baseline_min_days_for_ramp:
        any_checked = True
        early_dates, recent_dates = _split_halves(dates)
        early_values = [float(snapshot.daily_volume[d]) for d in early_dates]
        recent_values = [float(snapshot.daily_volume[d]) for d in recent_dates]
        early_mean = statistics.fmean(early_values)
        recent_mean = statistics.fmean(recent_values)

        volume_ratio_ok = (
            recent_mean >= early_mean * settings.baseline_ramp_ratio_threshold
            if early_mean > 0
            else recent_mean > 0
        )
        volume_ramp = volume_ratio_ok and _majority_at_or_above(recent_values, early_mean)

        early_ratios = [
            snapshot.daily_sensitive_count.get(d, 0) / snapshot.daily_volume[d] for d in early_dates
        ]
        recent_ratios = [
            snapshot.daily_sensitive_count.get(d, 0) / snapshot.daily_volume[d] for d in recent_dates
        ]
        early_ratio_mean = statistics.fmean(early_ratios) if early_ratios else 0.0
        recent_ratio_mean = statistics.fmean(recent_ratios) if recent_ratios else 0.0
        ratio_increase_ok = (
            recent_ratio_mean - early_ratio_mean
        ) >= settings.baseline_ramp_sensitive_ratio_increase_threshold
        sensitive_ratio_ramp = ratio_increase_ok and _majority_at_or_above(
            recent_ratios, early_ratio_mean
        )

        result = RampResult(
            volume_ramp_detected=volume_ramp,
            volume_early_mean=early_mean,
            volume_recent_mean=recent_mean,
            sensitive_ratio_ramp_detected=sensitive_ratio_ramp,
            sensitive_ratio_early_mean=early_ratio_mean,
            sensitive_ratio_recent_mean=recent_ratio_mean,
        )

    if snapshot.daily_volume and snapshot.long_term_daily_volume:
        recent_window_start = min(snapshot.daily_volume.keys())
        anchor_dates = sorted(
            d for d in snapshot.long_term_daily_volume if d < recent_window_start
        )
        if len(anchor_dates) >= settings.baseline_min_days_for_long_term_anchor:
            any_checked = True
            anchor_values = [float(snapshot.long_term_daily_volume[d]) for d in anchor_dates]
            anchor_mean = statistics.fmean(anchor_values)
            anchor_stdev = statistics.pstdev(anchor_values) if len(anchor_values) > 1 else 0.0
            recent_mean_for_drift = statistics.fmean(
                float(v) for v in snapshot.daily_volume.values()
            )
            drift_threshold = anchor_mean + settings.baseline_volume_stddev_multiplier * anchor_stdev
            long_term_drift = recent_mean_for_drift > drift_threshold

            result = RampResult(
                volume_ramp_detected=result.volume_ramp_detected,
                volume_early_mean=result.volume_early_mean,
                volume_recent_mean=result.volume_recent_mean,
                sensitive_ratio_ramp_detected=result.sensitive_ratio_ramp_detected,
                sensitive_ratio_early_mean=result.sensitive_ratio_early_mean,
                sensitive_ratio_recent_mean=result.sensitive_ratio_recent_mean,
                long_term_drift_detected=long_term_drift,
                long_term_anchor_mean=anchor_mean,
                long_term_recent_mean=recent_mean_for_drift,
            )

    if not any_checked:
        return None
    return result


# --------------------------------------------------------------------------------------
# Detection max-out Stage D — long-dwell / low-signal correlation.
#
# HONEST LIMIT: this closes the case where an actor's individual weak signals are too small
# for any existing detector but genuinely accumulate over months. It does NOT catch a
# disciplined attacker who never trips two of the categories below in the same ingestion
# batch, or who paces slowly enough that decay outruns accumulation — pure living-off-the-
# land within otherwise-normal patterns needs endpoint telemetry this system doesn't have.
# --------------------------------------------------------------------------------------

# Mirrors app.detections.data_exfiltration._TRANSFER_ACTIONS — duplicated, not imported,
# for the same reason _HOUR_TRACKED_ACTIONS above duplicates off_hours_access's constant:
# app.baselines must never depend on app.detections, only the other way around.
_LOW_SIGNAL_TRANSFER_ACTIONS = frozenset({"data_transfer", "file_download"})


def _is_allowlisted_destination(target: str | None) -> bool:
    """Mirrors app.detections.data_exfiltration._is_allowlisted — see
    _LOW_SIGNAL_TRANSFER_ACTIONS above for why this is duplicated rather than imported."""
    if target is None:
        return False
    return target in settings.exfil_allowlisted_destinations


@dataclass(frozen=True)
class WeakSignalContribution:
    """One batch's weak-signal read: which categories tripped, the raw point sum (used for
    cross-actor candidacy — see app.detections.cross_actor — regardless of co-occurrence),
    and chronic_points — the amount that actually feeds the long-lived decayed score, which
    is nonzero ONLY when 2+ distinct categories co-occur in the same batch (the anti-false-
    positive gate: a single recurring benign habit, however frequent, never reaches this by
    itself — see the Stage D plan's calibration section for the numeric justification)."""

    categories: frozenset[str] = field(default_factory=frozenset)
    raw_points: float = 0.0
    chronic_points: float = 0.0
    evidence_event_ids: list = field(default_factory=list)


def _compute_weak_signal_contribution(
    batch_events: list[ActivityEvent], baseline: BaselineSnapshot
) -> WeakSignalContribution:
    """Four independent checks, each structurally incapable of ALSO satisfying an existing
    detector's own firing condition (not just "below threshold by coincidence") — see the
    Stage D plan for why each boundary was chosen this way:
      - auth: 1..low_signal_auth_fail_ceiling auth_fail events in the batch — strictly below
        brute_force's 5-event burst floor.
      - transfer: a non-allowlisted transfer/download whose bytes are >0 but at or below
        exfil_large_transfer_bytes — below DATA_EXFIL_LARGE_TRANSFER's own floor.
      - sensitive: a first-ever touch of a sensitivity class, but ONLY while the baseline is
        still too new for app.detections.sensitive_resource_access's own cold-start gate —
        filling that detector's documented gap, not duplicating it.
      - hour: an atypical-hour event, but only once the baseline has enough history overall
        to make "atypical" meaningful (guards a brand-new baseline from flagging every hour).
    """
    categories: set[str] = set()
    evidence_ids: list = []

    auth_fails = [e for e in batch_events if e.action == "auth_fail"]
    if 1 <= len(auth_fails) <= settings.low_signal_auth_fail_ceiling:
        categories.add("auth")
        evidence_ids.extend(e.id for e in auth_fails if e.id is not None)

    for event in batch_events:
        if (
            event.action in _LOW_SIGNAL_TRANSFER_ACTIONS
            and (event.bytes or 0) > 0
            and (event.bytes or 0) <= settings.exfil_large_transfer_bytes
            and not _is_allowlisted_destination(event.target)
        ):
            categories.add("transfer")
            if event.id is not None:
                evidence_ids.append(event.id)

    if baseline.event_count < settings.baseline_min_events_for_resource_class:
        for event in batch_events:
            sensitivity_class = classify_resource_sensitivity(event.target)
            if sensitivity_class is not None and is_sensitive_class_first_seen(
                baseline, sensitivity_class
            ):
                categories.add("sensitive")
                if event.id is not None:
                    evidence_ids.append(event.id)

    if baseline.event_count >= settings.low_signal_min_events_for_hour_check:
        for event in batch_events:
            if event.action in _HOUR_TRACKED_ACTIONS and not is_typical_hour(
                baseline, event.timestamp.hour
            ):
                categories.add("hour")
                if event.id is not None:
                    evidence_ids.append(event.id)

    points_by_category = {
        "auth": settings.low_signal_points_auth_fail,
        "transfer": settings.low_signal_points_transfer,
        "sensitive": settings.low_signal_points_sensitive,
        "hour": settings.low_signal_points_hour,
    }
    raw_points = sum(points_by_category[c] for c in categories)
    chronic_points = (
        min(settings.low_signal_batch_cap, raw_points) if len(categories) >= 2 else 0.0
    )

    return WeakSignalContribution(
        categories=frozenset(categories),
        raw_points=raw_points,
        chronic_points=chronic_points,
        evidence_event_ids=evidence_ids,
    )


def decay_score(score: float, last_updated: datetime | None, now: datetime) -> float:
    """Exponential half-life decay — score * 0.5 ** (elapsed_days / half_life). No decay for
    a fresh baseline (last_updated is None) or a non-positive score."""
    if last_updated is None or score <= 0:
        return score
    elapsed_days = max(0.0, (now - last_updated).total_seconds() / 86400.0)
    return score * (0.5 ** (elapsed_days / settings.low_signal_half_life_days))


def project_suspicious_pattern_score(
    existing_score: float,
    last_updated: datetime | None,
    batch_events: list[ActivityEvent],
    baseline: BaselineSnapshot,
    now: datetime,
) -> tuple[float, WeakSignalContribution]:
    """Decays existing_score to `now`, then folds in this batch's contribution (if the
    co-occurrence gate passes), clipped at low_signal_score_cap. Deliberately a single pure
    function called identically by both the persistence path (app.api.routes.events, to
    compute the value it stores) and the firing decision
    (app.detections.low_signal_accumulation.evaluate) — both given the same baseline/batch
    inputs, so there is no one-batch lag between what's stored and what's evaluated."""
    decayed = decay_score(existing_score, last_updated, now)
    contribution = _compute_weak_signal_contribution(batch_events, baseline)
    new_score = min(settings.low_signal_score_cap, decayed + contribution.chronic_points)
    return new_score, contribution
