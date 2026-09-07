from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.core.config import settings
from app.detections.base import ActorEventWindow
from app.detections.cumulative_exfiltration import evaluate
from app.events.schema import ActivityEvent, EventAction
from app.models.schemas import Severity

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


# --------------------------------------------------------------------------------------
# Detection max-out Stage C — multi-window cumulative exfiltration.
# --------------------------------------------------------------------------------------


def _weekday_snap(dt: datetime) -> datetime:
    while dt.weekday() >= 5:
        dt += timedelta(days=1)
    return dt


def _paced_transfer_events(cycles: int, gap_days: int, bytes_per: int, actor: str) -> list[ActivityEvent]:
    t0 = datetime(2026, 6, 1, 15, 0, tzinfo=timezone.utc)
    events = []
    for cycle in range(cycles):
        day = _weekday_snap(t0 + timedelta(days=gap_days * cycle))
        events.append(
            ActivityEvent(
                timestamp=day,
                actor=actor,
                action=EventAction.DATA_TRANSFER,
                target=f"unfamiliar-host-{cycle % 4}.example.net",
                bytes=bytes_per,
                outcome="success",
            )
        )
    return events


def test_medium_window_fires_for_phase3_scenario2_cadence():
    """The exact phase 3 #2 cadence (280MB every 12 days) — never fires the 7-day short
    tier (verified: no window ever sees 2 transfers), fires the 30-day medium tier once
    enough cycles accumulate."""
    events = _paced_transfer_events(cycles=7, gap_days=12, bytes_per=280_000_000, actor="windowspread@corp.com")

    # No incident with fewer than 3 cycles (matches the numeric verification: medium tier
    # first crosses 600MB threshold at cycle 3, with 840MB across 3 transfers).
    window_early = ActorEventWindow(actor="windowspread@corp.com", events=events[:2])
    assert evaluate(window_early) == []

    window_full = ActorEventWindow(actor="windowspread@corp.com", events=events[:3])
    findings = evaluate(window_full)
    assert len(findings) == 1
    assert findings[0].id == "CUMULATIVE_EXFIL_VOLUME"
    assert findings[0].severity == Severity.HIGH  # ratio is 1.0 — all non-allowlisted


def test_long_window_fires_for_phase4_scenario4_cadence_when_medium_never_does():
    """The exact phase 4 #4 cadence (150MB every 12 days) — never crosses the medium
    tier's 600MB threshold at any point (3 cycles max in any 30-day window = 450MB), but
    the 90-day long tier still fires once 7+ cycles accumulate (1.05GB)."""
    events = _paced_transfer_events(cycles=9, gap_days=12, bytes_per=150_000_000, actor="distributed@corp.com")

    # Never fires through cycle 6 (matches the numeric verification).
    window_mid = ActorEventWindow(actor="distributed@corp.com", events=events[:6])
    assert evaluate(window_mid) == []

    window_full = ActorEventWindow(actor="distributed@corp.com", events=events[:7])
    findings = evaluate(window_full)
    assert len(findings) == 1
    assert "90-day" in findings[0].description


def test_single_legitimate_large_transfer_never_fires_regardless_of_tier():
    window = ActorEventWindow(
        actor="legit@corp.com",
        events=[_transfer(0, 900_000_000, target="client-sftp.example.net")],
    )
    assert evaluate(window) == []


def test_normal_ongoing_business_volume_stays_safe():
    """Modest, spread-out non-allowlisted transfers across 90 days, staying under every
    tier's threshold — the zero-false-positive control."""
    events = [_transfer(18 * i, 80_000_000, target=f"partner-{i}.example.net") for i in range(5)]
    window = ActorEventWindow(actor="lowslow@corp.com", events=events)
    assert evaluate(window) == []


def test_low_ratio_actor_scores_reduced_but_still_fires(monkeypatch):
    """Heavy legitimate allowlisted volume plus a modest non-allowlisted side-channel that
    still crosses the raw byte threshold — surfaced at reduced confidence, not suppressed."""
    monkeypatch.setattr(settings, "exfil_allowlisted_destinations", ["company-cloud.example.com"])
    t0 = datetime(2026, 6, 1, 15, 0, tzinfo=timezone.utc)
    events = []
    for i in range(3):
        events.append(
            ActivityEvent(
                timestamp=t0 + timedelta(days=10 * i), actor="mixed@corp.com",
                action=EventAction.DATA_TRANSFER, target="company-cloud.example.com",
                bytes=3_000_000_000, outcome="success",
            )
        )
    for i in range(3):
        events.append(
            ActivityEvent(
                timestamp=t0 + timedelta(days=10 * i + 5), actor="mixed@corp.com",
                action=EventAction.DATA_TRANSFER, target=f"client-{i}.example.net",
                bytes=400_000_000, outcome="success",
            )
        )
    window = ActorEventWindow(actor="mixed@corp.com", events=events)
    findings = evaluate(window)
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM
    assert findings[0].points < 30  # meaningfully reduced from the un-weighted ~55 points


def test_high_ratio_actor_gets_full_weight():
    t0 = datetime(2026, 6, 1, 15, 0, tzinfo=timezone.utc)
    events = [
        ActivityEvent(
            timestamp=t0 + timedelta(days=10 * i), actor="pure@corp.com",
            action=EventAction.DATA_TRANSFER, target=f"client-{i}.example.net",
            bytes=400_000_000, outcome="success",
        )
        for i in range(3)
    ]
    window = ActorEventWindow(actor="pure@corp.com", events=events)
    findings = evaluate(window)
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].points >= 50
