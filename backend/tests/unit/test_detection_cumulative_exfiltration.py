from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.core.config import settings
from app.detections.base import ActorEventWindow
from app.detections.cumulative_exfiltration import evaluate
from app.events.schema import ActivityEvent, EventAction

_TS = datetime(2026, 1, 6, 14, 0, tzinfo=timezone.utc)


def _transfer(day_offset: int, bytes_: int, target: str = "unfamiliar-storage-relay.example.net") -> ActivityEvent:
    return ActivityEvent(
        timestamp=_TS + timedelta(days=day_offset),
        actor="lowslow@corp.com",
        action=EventAction.DATA_TRANSFER,
        target=target,
        bytes=bytes_,
        outcome="success",
    )


def test_fires_for_many_small_transfers_summing_past_threshold():
    events = [_transfer(i, 44_000_000) for i in range(6)]  # 264M total, well under 500M each
    window = ActorEventWindow(actor="lowslow@corp.com", events=events)

    findings = evaluate(window)

    assert len(findings) == 1
    assert findings[0].id == "CUMULATIVE_EXFIL_VOLUME"


def test_does_not_fire_for_single_large_transfer_below_min_transfers():
    window = ActorEventWindow(actor="lowslow@corp.com", events=[_transfer(0, 300_000_000)])
    assert evaluate(window) == []


def test_does_not_fire_below_byte_threshold():
    events = [_transfer(i, 20_000_000) for i in range(5)]  # 100M total
    window = ActorEventWindow(actor="lowslow@corp.com", events=events)
    assert evaluate(window) == []


def test_does_not_fire_for_allowlisted_destination(monkeypatch):
    monkeypatch.setattr(settings, "exfil_allowlisted_destinations", ["trusted.example.com"])
    events = [_transfer(i, 44_000_000, target="trusted.example.com") for i in range(6)]
    window = ActorEventWindow(actor="lowslow@corp.com", events=events)
    assert evaluate(window) == []
