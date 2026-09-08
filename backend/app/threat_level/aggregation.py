"""Pure aggregation math for the early-warning sensor (Stage 1) — a live, decayed 0-100
per-actor Threat Level fed by precursor signals from BOTH the email pipeline (Case
verdicts, simulation clicks) and the events pipeline (Stage D's weak-signal categories,
real findings). No DB/SQLAlchemy here, same separation as app.baselines.aggregation;
app.threat_level.hooks is the thin DB-touching glue that calls into this module.

Deliberately its own package rather than folded into app.baselines: Threat Level spans both
the email and events domains, whereas ActorBaseline is events-only.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

from app.core.config import settings

# Kill-chain stage for each of Stage D's weak-signal categories (app.baselines.aggregation.
# WeakSignalContribution.categories) — delivery(1) < access(2) < collection(3) <
# exfiltration(4). Used both to tag AUTH_ANOMALY/FIRST_TIME_SENSITIVE_ACCESS/
# SMALL_UNFAMILIAR_TRANSFER signals and to decide the chain-forming bonus.
STAGE_BY_WEAK_CATEGORY = {"auth": 2, "hour": 2, "sensitive": 3, "transfer": 4}

STAGE_DELIVERY = 1
STAGE_ACCESS = 2
STAGE_COLLECTION = 3
STAGE_EXFILTRATION = 4

_BAND_NORMAL = "normal"
_BAND_ELEVATED = "elevated"
_BAND_ATTACK_FORMING = "attack_forming"

_TREND_RISING = "rising"
_TREND_FALLING = "falling"
_TREND_STEADY = "steady"

_TREND_DEADBAND = 3.0


@dataclass(frozen=True)
class Signal:
    """One precursor signal about to be folded into an actor's threat level. `points` here
    is the BASE value before any chain-forming bonus — project_threat_level applies that."""

    type: str
    stage: int
    points: float
    category: str
    timestamp: datetime
    description: str

    def to_dict(self) -> dict:
        return {
            "type": self.type,
            "stage": self.stage,
            "points": self.points,
            "category": self.category,
            "timestamp": self.timestamp.isoformat(),
            "description": self.description,
        }


def decay_score(score: float, last_updated: datetime | None, now: datetime) -> float:
    """Exponential half-life decay, same shape as app.baselines.aggregation.decay_score
    (Stage D) but against threat_level_half_life_days — deliberately much shorter (14 days
    by default) since this sensor is meant to react live, not track a months-long chronic
    pattern."""
    if last_updated is None or score <= 0:
        return score
    elapsed_days = max(0.0, (now - last_updated).total_seconds() / 86400.0)
    return score * (0.5 ** (elapsed_days / settings.threat_level_half_life_days))


def _trim_recent_signals(signals: list[dict], now: datetime) -> list[dict]:
    """Age-filters to threat_level_chain_window_days, then caps the count — both are needed:
    the age filter is what makes the chain-forming check meaningful (an ancient signal
    shouldn't still confer a chain bonus), the count cap is the bounded-state guard shared by
    every other per-actor JSON field in this codebase."""
    cutoff = now - timedelta(days=settings.threat_level_chain_window_days)
    fresh = [s for s in signals if datetime.fromisoformat(s["timestamp"]) >= cutoff]
    fresh.sort(key=lambda s: s["timestamp"])
    return fresh[-settings.threat_level_signal_history_cap :]


def apply_chain_bonus(new_signal: Signal, recent_signals: list[dict]) -> float:
    """Returns new_signal's points, multiplied by threat_level_chain_multiplier if the actor
    already has a signal at a STRICTLY EARLIER kill-chain stage among recent_signals (which
    the caller has already age-filtered to the chain window). Forward-progressing only — a
    repeat of the same or an earlier stage never gets the bonus; that asymmetry is what
    distinguishes "a chain forming" from mere repetition, which Stage D's own
    co-occurrence/decay already covers for the chronic case."""
    has_earlier_stage = any(s["stage"] < new_signal.stage for s in recent_signals)
    if has_earlier_stage:
        return new_signal.points * settings.threat_level_chain_multiplier
    return new_signal.points


def project_threat_level(
    existing_score: float,
    last_updated: datetime | None,
    recent_signals: list[dict],
    new_signals: list[Signal],
    now: datetime,
) -> tuple[float, list[dict]]:
    """Decays existing_score to `now`, then folds in each of new_signals (chain-bonus-aware,
    evaluated against the age-filtered recent_signals so signals within THE SAME batch also
    see each other in stage order), clipped to 100. Returns the new score and the updated,
    trimmed recent_signals list ready to persist."""
    decayed = decay_score(existing_score, last_updated, now)
    working_signals = _trim_recent_signals(recent_signals, now)

    added_points = 0.0
    for new_signal in sorted(new_signals, key=lambda s: s.stage):
        added_points += apply_chain_bonus(new_signal, working_signals)
        working_signals.append(new_signal.to_dict())

    new_score = min(100.0, decayed + added_points)
    updated_signals = _trim_recent_signals(working_signals, now)
    return new_score, updated_signals


def compute_band(score: float, recent_signals: list[dict]) -> str:
    """Early-warning sensor Stage 2 band classification. "Never one signal" is enforced
    structurally, not by a higher score bar: attack_forming requires BOTH score >=
    threat_level_elevated_at AND at least early_warning_min_corroborating_stages DISTINCT
    kill-chain stages represented among recent_signals — a chronically-repeated single-stage
    pattern stays "elevated" forever, however high its score climbs. Does not know about
    active_incident (a real-Incident-row override) — that needs a DB check, layered on top
    by the caller (see app.early_warning.hooks.has_active_incident)."""
    if score < settings.threat_level_elevated_at:
        return _BAND_NORMAL
    distinct_stages = {s["stage"] for s in recent_signals}
    if len(distinct_stages) >= settings.early_warning_min_corroborating_stages:
        return _BAND_ATTACK_FORMING
    return _BAND_ELEVATED


def _trim_score_history(history: dict[str, float], window_days: int = 30) -> dict[str, float]:
    if len(history) <= window_days:
        return dict(history)
    kept_dates = sorted(history.keys())[-window_days:]
    return {d: history[d] for d in kept_dates}


def record_score_snapshot(history: dict[str, float], score: float, now: datetime) -> dict[str, float]:
    """One snapshot per calendar day (overwriting same-day snapshots, same idiom as
    app.baselines.aggregation's daily_volume) — powers compute_trend below."""
    updated = dict(history)
    updated[now.date().isoformat()] = score
    return _trim_score_history(updated)


def compute_trend(score_history: dict[str, float], current_score: float, now: datetime) -> str:
    """Compares current_score against the snapshot at or just before
    threat_level_trend_window_days ago. No snapshot that old yet: "rising" if the actor has
    any score at all (they just appeared), else "steady" (nothing to trend)."""
    cutoff = now - timedelta(days=settings.threat_level_trend_window_days)
    candidates = [
        (datetime.fromisoformat(d), v)
        for d, v in score_history.items()
        if datetime.fromisoformat(d) <= cutoff
    ]
    if not candidates:
        return _TREND_RISING if current_score > 0 else _TREND_STEADY

    reference_score = max(candidates, key=lambda pair: pair[0])[1]
    delta = current_score - reference_score
    if delta > _TREND_DEADBAND:
        return _TREND_RISING
    if delta < -_TREND_DEADBAND:
        return _TREND_FALLING
    return _TREND_STEADY
