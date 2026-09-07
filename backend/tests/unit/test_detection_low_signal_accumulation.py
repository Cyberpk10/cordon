from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone

from app.baselines.aggregation import empty_baseline, project_suspicious_pattern_score, update_baseline
from app.detections.base import ActorEventWindow
from app.detections.low_signal_accumulation import evaluate
from app.events.schema import ActivityEvent, EventAction
from app.models.schemas import Severity

_BASE = datetime(2026, 3, 1, 15, 0, tzinfo=timezone.utc)


def _weekly_batch(week: int, actor: str = "patient@corp.com") -> list[ActivityEvent]:
    """One co-occurring batch: a sub-floor auth-fail blip + a small non-allowlisted
    transfer — 6 raw points/week (3+3), numerically verified (half_life=45d) to cross the
    default 40-point chronic threshold at week 11 (day 77), not before."""
    ts = _BASE + timedelta(weeks=week)
    return [
        ActivityEvent(timestamp=ts, actor=actor, action=EventAction.AUTH_FAIL, outcome="failure"),
        ActivityEvent(
            timestamp=ts,
            actor=actor,
            action=EventAction.DATA_TRANSFER,
            target=f"unfamiliar-host-{week % 4}.example.net",
            bytes=10_000_000,
            outcome="success",
        ),
    ]


def _replay(weeks: int, actor: str = "patient@corp.com") -> tuple:
    """Folds `weeks` weekly co-occurring batches through the same baseline/detection cycle
    events.py uses (load -> evaluate -> update -> persist score+timestamp), returning the
    LAST batch's findings and the resulting baseline."""
    baseline = empty_baseline(actor)
    findings: list = []
    for week in range(weeks):
        ts = _BASE + timedelta(weeks=week)
        batch = _weekly_batch(week, actor)
        window = ActorEventWindow(actor=actor, events=batch)
        findings = evaluate(window, baseline)
        score, _ = project_suspicious_pattern_score(
            baseline.suspicious_pattern_score, baseline.last_updated, batch, baseline, now=ts
        )
        baseline = update_baseline(baseline, batch)
        baseline = replace(baseline, suspicious_pattern_score=score, last_updated=ts)
    return findings, baseline


def test_does_not_fire_before_enough_weekly_cycles_accumulate():
    findings, baseline = _replay(10)
    assert findings == []
    assert baseline.suspicious_pattern_score < 40.0


def test_fires_once_enough_weekly_cycles_accumulate():
    findings, baseline = _replay(11)
    assert len(findings) == 1
    assert findings[0].id == "LOW_SIGNAL_PATTERN_ACCUMULATION"
    assert findings[0].severity in (Severity.MEDIUM, Severity.HIGH)
    assert baseline.suspicious_pattern_score > 40.0


def test_normal_employee_occasional_single_category_signals_never_fire():
    """Zero-false-positive control: a normal employee occasionally mistypes their password
    OR sends one odd transfer, but never both in the same batch, spread over 90+ days —
    the co-occurrence gate means none of this ever reaches the chronic accumulator."""
    actor = "normal@corp.com"
    baseline = empty_baseline(actor)
    findings: list = []
    for week in range(14):  # ~98 days
        ts = _BASE + timedelta(weeks=week)
        if week % 3 == 0:
            batch = [ActivityEvent(timestamp=ts, actor=actor, action=EventAction.AUTH_FAIL, outcome="failure")]
        elif week % 5 == 0:
            batch = [
                ActivityEvent(
                    timestamp=ts, actor=actor, action=EventAction.DATA_TRANSFER,
                    target="occasional-partner.example.net", bytes=8_000_000, outcome="success",
                )
            ]
        else:
            batch = [ActivityEvent(timestamp=ts, actor=actor, action=EventAction.LOGIN, outcome="success")]
        window = ActorEventWindow(actor=actor, events=batch)
        findings = evaluate(window, baseline)
        assert findings == []
        baseline = update_baseline(baseline, batch)
    assert baseline.suspicious_pattern_score == 0.0


def test_cold_start_degrades_to_no_finding():
    events = [
        ActivityEvent(timestamp=_BASE, actor="new@corp.com", action=EventAction.AUTH_FAIL, outcome="failure"),
        ActivityEvent(
            timestamp=_BASE, actor="new@corp.com", action=EventAction.DATA_TRANSFER,
            target="unfamiliar.example.net", bytes=5_000_000, outcome="success",
        ),
    ]
    window = ActorEventWindow(actor="new@corp.com", events=events)
    assert evaluate(window, None) == []  # one batch's worth is nowhere near the threshold


def test_empty_window_returns_no_findings():
    assert evaluate(ActorEventWindow(actor="alice@corp.com", events=[]), None) == []
