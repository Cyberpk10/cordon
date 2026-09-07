from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.baselines.aggregation import empty_baseline, update_baseline
from app.core.config import settings
from app.detections.base import ActorEventWindow
from app.detections.baseline_ramp import evaluate
from app.events.schema import ActivityEvent, EventAction
from app.models.schemas import Severity

_SAFE_MAX = 24


def _dated_event(base: datetime, day_offset: int, target: str) -> ActivityEvent:
    return ActivityEvent(
        timestamp=base + timedelta(days=day_offset),
        actor="alice@corp.com",
        action=EventAction.FILE_ACCESS,
        target=target,
        outcome="success",
    )


def _poisoned_baseline(monkeypatch):
    monkeypatch.setattr(settings, "sensitive_resource_prefixes_finance", ["finance/"])
    monkeypatch.setattr(settings, "baseline_min_days_for_ramp", 10)
    monkeypatch.setattr(settings, "baseline_ramp_ratio_threshold", 1.5)
    monkeypatch.setattr(settings, "baseline_ramp_sensitive_ratio_increase_threshold", 0.15)

    normal_targets = [f"shared/doc-{i}.docx" for i in range(5)]
    sensitive_targets = [f"finance/file-{i}.xlsx" for i in range(5)]
    ramp = [4, 4, 5, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 12, 13, 14]
    base = datetime(2026, 1, 5, 15, 0, tzinfo=timezone.utc)

    baseline = empty_baseline("alice@corp.com")
    for day_index, count in enumerate(ramp):
        n_sensitive = min(len(sensitive_targets), day_index // 4)
        n_normal = len(normal_targets) - n_sensitive
        pool = normal_targets[:n_normal] + sensitive_targets[:n_sensitive]
        events = [
            _dated_event(base, day_index, pool[i % len(pool)]) for i in range(count)
        ]
        baseline = update_baseline(baseline, events)
    return baseline


def test_verified_poisoning_ramp_fires_high_severity(monkeypatch):
    baseline = _poisoned_baseline(monkeypatch)
    window = ActorEventWindow(actor="alice@corp.com", events=[])
    findings = evaluate(window, baseline)
    assert len(findings) == 1
    assert findings[0].id == "BASELINE_RAMP_ANOMALY"
    assert findings[0].severity == Severity.HIGH
    assert findings[0].points > _SAFE_MAX


def test_volume_ramp_alone_stays_below_safe_max(monkeypatch):
    """Per the resolved weighting decision: raw daily-volume growth alone (organic, flat
    sensitive ratio) must never flip a verdict by itself."""
    monkeypatch.setattr(settings, "sensitive_resource_prefixes_finance", ["finance/"])
    monkeypatch.setattr(settings, "baseline_min_days_for_ramp", 10)
    monkeypatch.setattr(settings, "baseline_ramp_sensitive_ratio_increase_threshold", 0.15)
    base = datetime(2026, 1, 5, 15, 0, tzinfo=timezone.utc)
    counts = [4, 4, 4, 5, 4, 5, 5, 5, 6, 5, 8, 8, 9, 8, 9, 9, 9, 10, 10, 10]

    baseline = empty_baseline("alice@corp.com")
    for day_index, count in enumerate(counts):
        n_sensitive = round(count * 0.2)
        events = []
        for i in range(count):
            target = "finance/report.xlsx" if i < n_sensitive else "shared/notes.docx"
            events.append(_dated_event(base, day_index, target))
        baseline = update_baseline(baseline, events)

    window = ActorEventWindow(actor="alice@corp.com", events=[])
    findings = evaluate(window, baseline)
    if findings:
        assert findings[0].points < _SAFE_MAX
        assert findings[0].severity == Severity.MEDIUM


def test_insufficient_history_returns_empty():
    baseline = empty_baseline("alice@corp.com")
    window = ActorEventWindow(actor="alice@corp.com", events=[])
    assert evaluate(window, baseline) == []


def test_no_baseline_returns_empty():
    window = ActorEventWindow(actor="alice@corp.com", events=[])
    assert evaluate(window, None) == []
