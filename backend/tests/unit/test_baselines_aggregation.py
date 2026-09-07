from __future__ import annotations

from datetime import datetime, timezone

from app.baselines.aggregation import (
    empty_baseline,
    evaluate_ramp_anomaly,
    is_known_location,
    is_sensitive_class_first_seen,
    is_typical_hour,
    is_volume_anomalous,
    update_baseline,
)
from app.core.config import settings
from app.events.schema import ActivityEvent, EventAction, GeoLocation


def _event(
    day: int,
    hour: int,
    action: EventAction,
    outcome: str | None = "success",
    country: str | None = None,
    source_ip: str | None = None,
    target: str | None = None,
) -> ActivityEvent:
    return ActivityEvent(
        timestamp=datetime(2026, 1, day, hour, 0, tzinfo=timezone.utc),
        actor="alice@corp.com",
        action=action,
        outcome=outcome,
        geo=GeoLocation(country=country) if country else None,
        source_ip=source_ip,
        target=target,
    )


def test_empty_baseline_has_zero_counts():
    baseline = empty_baseline("alice@corp.com")
    assert baseline.event_count == 0
    assert baseline.hour_counts == [0] * 24
    assert baseline.location_counts == {}
    assert baseline.daily_volume == {}


def test_update_baseline_increments_hour_counts_for_sensitive_actions():
    baseline = empty_baseline("alice@corp.com")
    updated = update_baseline(baseline, [_event(6, 9, EventAction.LOGIN)])
    assert updated.hour_counts[9] == 1
    assert updated.event_count == 1


def test_update_baseline_ignores_logout_for_hour_counts():
    baseline = empty_baseline("alice@corp.com")
    updated = update_baseline(baseline, [_event(6, 9, EventAction.LOGOUT)])
    assert updated.hour_counts[9] == 0
    assert updated.event_count == 1  # still counts toward general history


def test_update_baseline_tracks_location_and_ip_for_successful_logins():
    baseline = empty_baseline("alice@corp.com")
    updated = update_baseline(
        baseline, [_event(6, 9, EventAction.LOGIN, country="US", source_ip="203.0.113.5")]
    )
    assert updated.location_counts == {"US": 1}
    assert updated.ip_counts == {"203.0.113.5": 1}


def test_update_baseline_ignores_failed_logins_for_location():
    baseline = empty_baseline("alice@corp.com")
    updated = update_baseline(
        baseline, [_event(6, 9, EventAction.LOGIN, outcome="failure", country="US")]
    )
    assert updated.location_counts == {}


def test_update_baseline_increments_daily_volume_for_file_actions():
    baseline = empty_baseline("alice@corp.com")
    events = [_event(6, 9, EventAction.FILE_ACCESS), _event(6, 10, EventAction.FILE_DOWNLOAD)]
    updated = update_baseline(baseline, events)
    assert updated.daily_volume == {"2026-01-06": 2}


def test_update_baseline_trims_daily_volume_to_rolling_window(monkeypatch):
    monkeypatch.setattr(settings, "baseline_daily_volume_window_days", 3)
    baseline = empty_baseline("alice@corp.com")
    for day in range(1, 6):  # 5 distinct days, window is 3
        baseline = update_baseline(baseline, [_event(day, 9, EventAction.FILE_ACCESS)])
    assert len(baseline.daily_volume) == 3
    assert set(baseline.daily_volume.keys()) == {"2026-01-03", "2026-01-04", "2026-01-05"}


def test_is_typical_hour_respects_min_occurrences_threshold(monkeypatch):
    monkeypatch.setattr(settings, "baseline_min_hour_occurrences", 2)
    baseline = empty_baseline("alice@corp.com")
    baseline = update_baseline(baseline, [_event(6, 9, EventAction.LOGIN)])
    assert is_typical_hour(baseline, 9) is False  # seen once, threshold is 2
    baseline = update_baseline(baseline, [_event(7, 9, EventAction.LOGIN)])
    assert is_typical_hour(baseline, 9) is True


def test_is_known_location_true_only_when_seen():
    baseline = empty_baseline("alice@corp.com")
    baseline = update_baseline(baseline, [_event(6, 9, EventAction.LOGIN, country="US")])
    assert is_known_location(baseline, "US") is True
    assert is_known_location(baseline, "RU") is False


def test_is_volume_anomalous_returns_none_under_cold_start(monkeypatch):
    monkeypatch.setattr(settings, "baseline_min_days_for_volume", 5)
    baseline = empty_baseline("alice@corp.com")
    baseline = update_baseline(baseline, [_event(6, 9, EventAction.FILE_ACCESS)])
    assert is_volume_anomalous(baseline, 100) is None


def test_is_volume_anomalous_fires_above_mean_plus_stddev(monkeypatch):
    monkeypatch.setattr(settings, "baseline_min_days_for_volume", 3)
    monkeypatch.setattr(settings, "baseline_volume_stddev_multiplier", 2.0)
    baseline = empty_baseline("alice@corp.com")
    # Establish a consistent baseline of 3 file-access events/day for 5 days.
    for day in range(1, 6):
        events = [_event(day, 9, EventAction.FILE_ACCESS) for _ in range(3)]
        baseline = update_baseline(baseline, events)
    assert is_volume_anomalous(baseline, 3) is False  # matches established pattern
    assert is_volume_anomalous(baseline, 50) is True  # wildly outside established pattern


# --------------------------------------------------------------------------------------
# Detection max-out Stage B — resource sensitivity + anti-poisoning ramp detection.
# --------------------------------------------------------------------------------------

from datetime import timedelta  # noqa: E402


def _dated_event(
    base: datetime, day_offset: int, hour: int, action: EventAction, target: str | None = None
) -> ActivityEvent:
    """Like _event above, but spans arbitrarily many days via a base date + offset instead
    of a literal day-of-month int — needed for ramp tests that run longer than one month."""
    return ActivityEvent(
        timestamp=base + timedelta(days=day_offset, hours=hour - base.hour),
        actor="alice@corp.com",
        action=action,
        outcome="success",
        target=target,
    )


def test_update_baseline_tracks_sensitive_classes_seen(monkeypatch):
    monkeypatch.setattr(settings, "sensitive_resource_prefixes_finance", ["finance/"])
    baseline = empty_baseline("alice@corp.com")
    baseline = update_baseline(
        baseline, [_event(6, 9, EventAction.FILE_ACCESS, target="finance/report.xlsx")]
    )
    assert baseline.sensitive_classes_seen == frozenset({"finance"})
    assert is_sensitive_class_first_seen(baseline, "hr") is True
    assert is_sensitive_class_first_seen(baseline, "finance") is False


def test_update_baseline_ignores_non_sensitive_targets_for_classes(monkeypatch):
    monkeypatch.setattr(settings, "sensitive_resource_prefixes_finance", ["finance/"])
    baseline = empty_baseline("alice@corp.com")
    baseline = update_baseline(
        baseline, [_event(6, 9, EventAction.FILE_ACCESS, target="shared/notes.docx")]
    )
    assert baseline.sensitive_classes_seen == frozenset()


def test_update_baseline_tracks_daily_sensitive_count(monkeypatch):
    monkeypatch.setattr(settings, "sensitive_resource_prefixes_finance", ["finance/"])
    baseline = empty_baseline("alice@corp.com")
    events = [
        _event(6, 9, EventAction.FILE_ACCESS, target="finance/a.xlsx"),
        _event(6, 10, EventAction.FILE_ACCESS, target="shared/b.docx"),
    ]
    baseline = update_baseline(baseline, events)
    assert baseline.daily_sensitive_count == {"2026-01-06": 1}
    assert baseline.daily_volume == {"2026-01-06": 2}


def test_evaluate_ramp_anomaly_returns_none_under_cold_start(monkeypatch):
    monkeypatch.setattr(settings, "baseline_min_days_for_ramp", 10)
    monkeypatch.setattr(settings, "baseline_min_days_for_long_term_anchor", 20)
    baseline = empty_baseline("alice@corp.com")
    baseline = update_baseline(baseline, [_event(6, 9, EventAction.FILE_ACCESS)])
    assert evaluate_ramp_anomaly(baseline) is None


def test_evaluate_ramp_anomaly_fires_on_the_verified_poisoning_ramp(monkeypatch):
    """Regression-pins the exact ramp used by scripts/attack_sim_phase3.py and
    attack_sim_phase4.py: a 20-day sequence [4,4,5,4,5,5,6,6,7,7,8,8,9,9,10,10,11,12,13,14]
    with sensitive-share stepping 0%->20%->40%->60%->80% every 4 days. Verified numerically
    (early-half volume mean 5.3 -> recent-half 10.4; early-half sensitive ratio ~13% ->
    recent-half ~58%) before writing this test, not assumed."""
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
            _dated_event(base, day_index, 15, EventAction.FILE_ACCESS, target=pool[i % len(pool)])
            for i in range(count)
        ]
        baseline = update_baseline(baseline, events)

    result = evaluate_ramp_anomaly(baseline)
    assert result is not None
    assert result.volume_ramp_detected is True
    assert result.sensitive_ratio_ramp_detected is True


def test_evaluate_ramp_anomaly_does_not_fire_on_flat_noisy_series(monkeypatch):
    monkeypatch.setattr(settings, "sensitive_resource_prefixes_finance", ["finance/"])
    monkeypatch.setattr(settings, "baseline_min_days_for_ramp", 10)
    base = datetime(2026, 1, 5, 15, 0, tzinfo=timezone.utc)
    counts = [4, 5, 6, 5, 4, 6, 5, 4, 5, 6, 5, 4, 6, 5, 4, 5, 6, 5, 4, 5]

    baseline = empty_baseline("alice@corp.com")
    for day_index, count in enumerate(counts):
        events = [
            _dated_event(base, day_index, 15, EventAction.FILE_ACCESS, target="shared/doc.docx")
            for _ in range(count)
        ]
        baseline = update_baseline(baseline, events)

    result = evaluate_ramp_anomaly(baseline)
    assert result is None or not result.any_detected


def test_evaluate_ramp_anomaly_does_not_fire_on_organic_growth_with_flat_ratio(monkeypatch):
    """A benign employee whose raw volume organically grows over weeks, but whose SHARE of
    sensitive-class access stays flat, must not trip the (higher-weighted) ratio-ramp check —
    only the low-weighted volume-ramp signal, if anything, per the resolved product decision
    that raw volume growth alone is common and often benign."""
    monkeypatch.setattr(settings, "sensitive_resource_prefixes_finance", ["finance/"])
    monkeypatch.setattr(settings, "baseline_min_days_for_ramp", 10)
    monkeypatch.setattr(settings, "baseline_ramp_sensitive_ratio_increase_threshold", 0.15)
    base = datetime(2026, 1, 5, 15, 0, tzinfo=timezone.utc)
    counts = [4, 4, 4, 5, 4, 5, 5, 5, 6, 5, 6, 6, 7, 6, 7, 7, 7, 8, 8, 8]

    baseline = empty_baseline("alice@corp.com")
    for day_index, count in enumerate(counts):
        n_sensitive = round(count * 0.2)
        events = []
        for i in range(count):
            target = "finance/report.xlsx" if i < n_sensitive else "shared/notes.docx"
            events.append(_dated_event(base, day_index, 15, EventAction.FILE_ACCESS, target=target))
        baseline = update_baseline(baseline, events)

    result = evaluate_ramp_anomaly(baseline)
    assert result is not None
    assert result.sensitive_ratio_ramp_detected is False


def test_evaluate_ramp_anomaly_long_term_drift_requires_data_older_than_recent_window(monkeypatch):
    monkeypatch.setattr(settings, "baseline_daily_volume_window_days", 30)
    monkeypatch.setattr(settings, "baseline_long_term_window_days", 180)
    monkeypatch.setattr(settings, "baseline_min_days_for_long_term_anchor", 20)
    monkeypatch.setattr(settings, "baseline_min_days_for_ramp", 999)  # disable the within-window check
    monkeypatch.setattr(settings, "baseline_volume_stddev_multiplier", 2.0)
    base = datetime(2026, 1, 5, 15, 0, tzinfo=timezone.utc)

    baseline = empty_baseline("alice@corp.com")
    # 25 "old" days at a steady, low volume — will age out of the 30-day recent window once
    # 30+ more days of activity are added, becoming the long-term anchor.
    for day_index in range(25):
        events = [
            _dated_event(base, day_index, 15, EventAction.FILE_ACCESS, target="shared/doc.docx")
            for _ in range(3)
        ]
        baseline = update_baseline(baseline, events)

    # Not enough NEW data yet for the recent window to have rolled the old days out —
    # long-term drift must not fire prematurely.
    result_before = evaluate_ramp_anomaly(baseline)
    assert result_before is None or result_before.long_term_drift_detected is False

    # 35 more days at a much higher, sustained volume — old low-volume days roll out of the
    # 30-day recent window entirely, leaving them ONLY in the long-term series as the anchor.
    for day_index in range(25, 60):
        events = [
            _dated_event(base, day_index, 15, EventAction.FILE_ACCESS, target="shared/doc.docx")
            for _ in range(12)
        ]
        baseline = update_baseline(baseline, events)

    result_after = evaluate_ramp_anomaly(baseline)
    assert result_after is not None
    assert result_after.long_term_drift_detected is True
