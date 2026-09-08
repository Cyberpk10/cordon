from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.core.config import settings
from app.threat_level.aggregation import (
    STAGE_ACCESS,
    STAGE_COLLECTION,
    STAGE_DELIVERY,
    STAGE_EXFILTRATION,
    Signal,
    compute_band,
    compute_trend,
    decay_score,
    project_threat_level,
    record_score_snapshot,
)

_BASE = datetime(2026, 3, 1, 12, 0)


def _signal(stage: int, points: float, ts: datetime, sig_type: str = "TEST") -> Signal:
    return Signal(type=sig_type, stage=stage, points=points, category="test", timestamp=ts, description="d")


# --------------------------------------------------------------------------------------
# decay_score
# --------------------------------------------------------------------------------------


def test_decay_score_halves_after_one_half_life(monkeypatch):
    monkeypatch.setattr(settings, "threat_level_half_life_days", 14.0)
    later = _BASE + timedelta(days=14)
    assert abs(decay_score(20.0, _BASE, later) - 10.0) < 0.01


def test_decay_score_no_decay_without_last_updated():
    assert decay_score(20.0, None, _BASE) == 20.0


def test_decay_score_no_decay_for_zero_score():
    assert decay_score(0.0, _BASE, _BASE + timedelta(days=100)) == 0.0


# --------------------------------------------------------------------------------------
# project_threat_level / chain-forming bonus
# --------------------------------------------------------------------------------------


def test_isolated_single_signal_stays_normal(monkeypatch):
    monkeypatch.setattr(settings, "threat_level_elevated_at", 25.0)
    score, signals = project_threat_level(0.0, None, [], [_signal(STAGE_ACCESS, 8.0, _BASE)], now=_BASE)
    assert score == 8.0
    assert compute_band(score, signals) == "normal"

    # A week later, decayed further, still normal.
    later = _BASE + timedelta(days=7)
    decayed = decay_score(score, _BASE, later)
    assert decayed < 8.0
    assert compute_band(decayed, signals) == "normal"


def test_chain_forming_progression_reaches_attack_forming_before_any_incident(monkeypatch):
    """The exact numerically-verified progression from the Stage 1 plan: auth (day 0) ->
    sensitive-access (day 5, chain bonus) -> transfer (day 8, chain bonus) reaches ~35 by
    day 8 — crosses the elevated floor (25) AND spans 3 distinct kill-chain stages, so Stage
    2's corroboration gate classifies it as ATTACK_FORMING, not just elevated — while each
    individual signal is, by construction, one of Stage D's sub-floor weak categories that
    never fires a real detector on its own."""
    monkeypatch.setattr(settings, "threat_level_half_life_days", 14.0)
    monkeypatch.setattr(settings, "threat_level_chain_multiplier", 1.8)
    monkeypatch.setattr(settings, "threat_level_chain_window_days", 21)
    monkeypatch.setattr(settings, "threat_level_signal_history_cap", 20)
    monkeypatch.setattr(settings, "early_warning_min_corroborating_stages", 2)

    day0 = _BASE
    day5 = _BASE + timedelta(days=5)
    day8 = _BASE + timedelta(days=8)

    score, signals = project_threat_level(0.0, None, [], [_signal(STAGE_ACCESS, 8.0, day0)], now=day0)
    assert round(score, 1) == 8.0
    assert compute_band(score, signals) == "normal"

    score, signals = project_threat_level(
        score, day0, signals, [_signal(STAGE_COLLECTION, 10.0, day5)], now=day5
    )
    assert round(score, 2) == 24.25  # chain bonus applied: 10 * 1.8 = 18, + decayed 6.25
    assert compute_band(score, signals) == "normal"  # still just under the elevated floor

    score, signals = project_threat_level(
        score, day5, signals, [_signal(STAGE_EXFILTRATION, 8.0, day8)], now=day8
    )
    assert round(score, 1) == 35.3
    assert compute_band(score, signals) == "attack_forming"


def test_chain_bonus_does_not_apply_to_same_or_earlier_stage(monkeypatch):
    monkeypatch.setattr(settings, "threat_level_chain_multiplier", 1.8)
    monkeypatch.setattr(settings, "threat_level_chain_window_days", 21)

    score, signals = project_threat_level(0.0, None, [], [_signal(STAGE_COLLECTION, 10.0, _BASE)], now=_BASE)
    later = _BASE + timedelta(days=2)
    # A SAME-stage repeat, and an EARLIER-stage signal, neither gets the forward-chain bonus.
    score2, _ = project_threat_level(
        score, _BASE, signals, [_signal(STAGE_COLLECTION, 10.0, later)], now=later
    )
    score3, _ = project_threat_level(
        score, _BASE, signals, [_signal(STAGE_DELIVERY, 10.0, later)], now=later
    )
    assert round(score2, 1) == round(score3, 1)  # both un-boosted, un-chained


def test_coincidental_two_signal_pairing_stays_under_elevated(monkeypatch):
    """Zero-false-positive worst case from calibration: two isolated, unrelated benign
    signals happening to coincide (even simultaneously, zero decay) must not itself cross
    into ELEVATED — only a genuine third coincidence would, which is documented as an
    accepted, calibrated residual, not eliminated outright."""
    monkeypatch.setattr(settings, "threat_level_half_life_days", 14.0)
    monkeypatch.setattr(settings, "threat_level_chain_multiplier", 1.8)
    monkeypatch.setattr(settings, "threat_level_chain_window_days", 21)
    monkeypatch.setattr(settings, "threat_level_elevated_at", 25.0)

    score, signals = project_threat_level(0.0, None, [], [_signal(STAGE_ACCESS, 8.0, _BASE)], now=_BASE)
    score, signals = project_threat_level(
        score, _BASE, signals, [_signal(STAGE_EXFILTRATION, 8.0, _BASE)], now=_BASE
    )
    assert round(score, 1) == 22.4
    # Below the elevated floor even though 2 distinct stages ARE present — the score floor
    # (itself validated against exactly this worst case) is what screens this out, not the
    # corroboration gate.
    assert compute_band(score, signals) == "normal"


def test_score_clips_at_one_hundred():
    score, _ = project_threat_level(
        95.0, _BASE, [], [_signal(STAGE_EXFILTRATION, 50.0, _BASE)], now=_BASE
    )
    assert score == 100.0


def test_recent_signals_are_trimmed_past_the_chain_window(monkeypatch):
    monkeypatch.setattr(settings, "threat_level_chain_window_days", 21)
    old_signal = {
        "type": "OLD", "stage": STAGE_DELIVERY, "points": 5.0, "category": "x",
        "timestamp": (_BASE - timedelta(days=30)).isoformat(), "description": "old",
    }
    _, updated = project_threat_level(
        0.0, None, [old_signal], [_signal(STAGE_ACCESS, 8.0, _BASE)], now=_BASE
    )
    assert all(s["type"] != "OLD" for s in updated)


def test_recent_signals_are_capped_at_configured_size(monkeypatch):
    monkeypatch.setattr(settings, "threat_level_signal_history_cap", 3)
    monkeypatch.setattr(settings, "threat_level_chain_window_days", 365)
    existing: list[dict] = []
    score = 0.0
    last_updated = None
    for i in range(5):
        ts = _BASE + timedelta(days=i)
        score, existing = project_threat_level(
            score, last_updated, existing, [_signal(STAGE_ACCESS, 1.0, ts)], now=ts
        )
        last_updated = ts
    assert len(existing) == 3


# --------------------------------------------------------------------------------------
# compute_band — early-warning sensor Stage 2. "Never one signal": attack_forming requires
# BOTH the score floor AND multi-stage corroboration, never a higher score alone.
# --------------------------------------------------------------------------------------


def _signals_at_stages(*stages: int) -> list[dict]:
    return [
        {"type": "TEST", "stage": stage, "points": 1.0, "category": "test",
         "timestamp": _BASE.isoformat(), "description": "d"}
        for stage in stages
    ]


def test_compute_band_normal_below_elevated_floor(monkeypatch):
    monkeypatch.setattr(settings, "threat_level_elevated_at", 25.0)
    assert compute_band(0.0, _signals_at_stages(STAGE_ACCESS, STAGE_EXFILTRATION)) == "normal"
    assert compute_band(24.9, _signals_at_stages(STAGE_ACCESS, STAGE_EXFILTRATION)) == "normal"


def test_compute_band_elevated_above_floor_with_single_stage(monkeypatch):
    """A single, very high-value signal (one stage only) never reaches attack_forming, no
    matter how high the score — this is the structural "never one signal" bar."""
    monkeypatch.setattr(settings, "threat_level_elevated_at", 25.0)
    monkeypatch.setattr(settings, "early_warning_min_corroborating_stages", 2)
    assert compute_band(30.0, _signals_at_stages(STAGE_ACCESS)) == "elevated"
    assert compute_band(100.0, _signals_at_stages(STAGE_ACCESS, STAGE_ACCESS)) == "elevated"


def test_compute_band_attack_forming_requires_both_floor_and_corroboration(monkeypatch):
    monkeypatch.setattr(settings, "threat_level_elevated_at", 25.0)
    monkeypatch.setattr(settings, "early_warning_min_corroborating_stages", 2)
    assert compute_band(30.0, _signals_at_stages(STAGE_ACCESS, STAGE_COLLECTION)) == "attack_forming"
    # Multi-stage but under the score floor stays normal — corroboration alone isn't enough.
    assert compute_band(10.0, _signals_at_stages(STAGE_ACCESS, STAGE_COLLECTION)) == "normal"


def test_compute_band_chronic_single_stage_repetition_never_forms(monkeypatch):
    """Mirrors Stage 1's own zero-FP philosophy: a chronically-repeated SAME-stage pattern
    can drive the score arbitrarily high without ever corroborating a forming chain."""
    monkeypatch.setattr(settings, "threat_level_elevated_at", 25.0)
    monkeypatch.setattr(settings, "early_warning_min_corroborating_stages", 2)
    many_same_stage = _signals_at_stages(*([STAGE_ACCESS] * 10))
    assert compute_band(95.0, many_same_stage) == "elevated"


# --------------------------------------------------------------------------------------
# compute_trend
# --------------------------------------------------------------------------------------


def test_compute_trend_rising_with_no_history_and_nonzero_score():
    assert compute_trend({}, 10.0, _BASE) == "rising"


def test_compute_trend_steady_with_no_history_and_zero_score():
    assert compute_trend({}, 0.0, _BASE) == "steady"


def test_compute_trend_rising_falling_steady(monkeypatch):
    monkeypatch.setattr(settings, "threat_level_trend_window_days", 7)
    week_ago = (_BASE - timedelta(days=8)).date().isoformat()

    history_rising = {week_ago: 5.0}
    assert compute_trend(history_rising, 20.0, _BASE) == "rising"

    history_falling = {week_ago: 20.0}
    assert compute_trend(history_falling, 5.0, _BASE) == "falling"

    history_steady = {week_ago: 10.0}
    assert compute_trend(history_steady, 11.0, _BASE) == "steady"


def test_record_score_snapshot_overwrites_same_day_and_trims():
    history: dict[str, float] = {}
    for i in range(35):
        history = record_score_snapshot(history, float(i), _BASE + timedelta(days=i))
    assert len(history) == 30
