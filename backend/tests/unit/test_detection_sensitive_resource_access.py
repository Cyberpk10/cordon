from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.baselines.aggregation import BaselineSnapshot, empty_baseline, update_baseline
from app.core.config import settings
from app.detections.base import ActorEventWindow
from app.detections.sensitive_resource_access import evaluate
from app.events.schema import ActivityEvent, EventAction

_BASE = datetime(2026, 1, 6, 15, 0, tzinfo=timezone.utc)


def _event(target: str, minute: int = 0) -> ActivityEvent:
    return ActivityEvent(
        timestamp=_BASE + timedelta(minutes=minute),
        actor="alice@corp.com",
        action=EventAction.FILE_ACCESS,
        target=target,
        outcome="success",
    )


def _established_baseline(monkeypatch, min_events: int = 5) -> BaselineSnapshot:
    monkeypatch.setattr(settings, "baseline_min_events_for_resource_class", min_events)
    monkeypatch.setattr(settings, "sensitive_resource_prefixes_finance", ["finance/"])
    monkeypatch.setattr(settings, "sensitive_resource_prefixes_hr", ["hr/"])
    monkeypatch.setattr(settings, "sensitive_resource_prefixes_legal", ["legal/"])
    baseline = empty_baseline("alice@corp.com")
    for day in range(1, 6):
        events = [
            ActivityEvent(
                timestamp=_BASE.replace(day=day, hour=15, minute=i),
                actor="alice@corp.com",
                action=EventAction.FILE_ACCESS,
                target=f"shared/doc-{i}.docx",
                outcome="success",
            )
            for i in range(4)
        ]
        baseline = update_baseline(baseline, events)
    return baseline


def test_first_time_single_class_access_stays_below_safe_max(monkeypatch):
    baseline = _established_baseline(monkeypatch)
    window = ActorEventWindow(actor="alice@corp.com", events=[_event("finance/q3.xlsx")])
    findings = evaluate(window, baseline)
    assert len(findings) == 1
    assert findings[0].id == "SENSITIVE_RESOURCE_FIRST_ACCESS"
    assert findings[0].points < 24  # SAFE_MAX — a single new class must not flip a verdict alone


def test_multi_class_sweep_clears_suspicious_max(monkeypatch):
    """The exact Phase 2 #4 shape: finance+HR+legal touched all at once, at normal volume."""
    baseline = _established_baseline(monkeypatch)
    window = ActorEventWindow(
        actor="alice@corp.com",
        events=[
            _event("finance/q3-budget-actuals.xlsx", 0),
            _event("finance/payroll-adjustments.xlsx", 3),
            _event("hr/comp-review-2026.xlsx", 6),
            _event("hr/pending-terminations.docx", 9),
            _event("legal/pending-litigation-notes.docx", 12),
        ],
    )
    findings = evaluate(window, baseline)
    assert len(findings) == 1
    assert findings[0].points > 24  # clears SAFE_MAX comfortably


def test_repeat_access_to_already_seen_class_does_not_fire(monkeypatch):
    monkeypatch.setattr(settings, "baseline_min_events_for_resource_class", 5)
    monkeypatch.setattr(settings, "sensitive_resource_prefixes_finance", ["finance/"])
    baseline = empty_baseline("alice@corp.com")
    for day in range(1, 6):
        events = [
            ActivityEvent(
                timestamp=_BASE.replace(day=day, hour=15),
                actor="alice@corp.com",
                action=EventAction.FILE_ACCESS,
                target="finance/monthly-report.xlsx",
                outcome="success",
            )
        ]
        baseline = update_baseline(baseline, events)

    window = ActorEventWindow(actor="alice@corp.com", events=[_event("finance/another-report.xlsx")])
    assert evaluate(window, baseline) == []


def test_cold_start_never_fires(monkeypatch):
    monkeypatch.setattr(settings, "baseline_min_events_for_resource_class", 5)
    monkeypatch.setattr(settings, "sensitive_resource_prefixes_finance", ["finance/"])
    window = ActorEventWindow(actor="alice@corp.com", events=[_event("finance/q3.xlsx")])
    assert evaluate(window, None) == []
    assert evaluate(window, empty_baseline("alice@corp.com")) == []


def test_non_sensitive_target_never_fires(monkeypatch):
    baseline = _established_baseline(monkeypatch)
    window = ActorEventWindow(actor="alice@corp.com", events=[_event("shared/new-doc.docx")])
    assert evaluate(window, baseline) == []
