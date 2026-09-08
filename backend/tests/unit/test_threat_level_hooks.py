from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from app.baselines.aggregation import WeakSignalContribution, empty_baseline, update_baseline
from app.core.config import settings
from app.db.models import ActorThreatLevel, Case
from app.events.schema import ActivityEvent, EventAction, GeoLocation
from app.models.schemas import Finding, Severity
from app.threat_level.hooks import (
    record_case_signal,
    record_event_batch_signals,
    record_simulation_click,
)

_BASE = datetime(2026, 3, 1, 12, 0)


def _row(db_session, account_id, actor):
    return (
        db_session.query(ActorThreatLevel)
        .filter(ActorThreatLevel.account_id == account_id, ActorThreatLevel.actor == actor)
        .first()
    )


def _make_case(account_id, verdict: str, to_addresses: list[str], score: int = 40) -> Case:
    return Case(
        id=uuid.uuid4(),
        account_id=account_id,
        filename="test.eml",
        verdict=verdict,
        score=score,
        to_addresses=to_addresses,
    )


# --------------------------------------------------------------------------------------
# record_case_signal
# --------------------------------------------------------------------------------------


def test_record_case_signal_ignores_safe_verdict(db_session, test_account):
    account_id = test_account.account.id
    case = _make_case(account_id, "safe", ["alice@corp.com"])
    record_case_signal(db_session, account_id, case)
    db_session.commit()
    assert _row(db_session, account_id, "alice@corp.com") is None


def test_record_case_signal_fires_for_suspicious_and_malicious(db_session, test_account, monkeypatch):
    monkeypatch.setattr(settings, "threat_level_points_phishing_received_suspicious", 10.0)
    monkeypatch.setattr(settings, "threat_level_points_phishing_received_malicious", 18.0)
    account_id = test_account.account.id

    case1 = _make_case(account_id, "suspicious", ["bob@corp.com"])
    record_case_signal(db_session, account_id, case1)
    db_session.commit()
    row = _row(db_session, account_id, "bob@corp.com")
    assert row.current_score == 10.0

    case2 = _make_case(account_id, "malicious", ["carol@corp.com"])
    record_case_signal(db_session, account_id, case2)
    db_session.commit()
    row2 = _row(db_session, account_id, "carol@corp.com")
    assert row2.current_score == 18.0


def test_record_case_signal_covers_every_recipient(db_session, test_account):
    account_id = test_account.account.id
    case = _make_case(account_id, "malicious", ["dave@corp.com", "erin@corp.com"])
    record_case_signal(db_session, account_id, case)
    db_session.commit()
    assert _row(db_session, account_id, "dave@corp.com") is not None
    assert _row(db_session, account_id, "erin@corp.com") is not None


# --------------------------------------------------------------------------------------
# record_simulation_click
# --------------------------------------------------------------------------------------


def test_record_simulation_click_creates_signal(db_session, test_account, monkeypatch):
    monkeypatch.setattr(settings, "threat_level_points_simulation_clicked", 12.0)
    account_id = test_account.account.id
    record_simulation_click(db_session, account_id, "frank@corp.com")
    db_session.commit()
    row = _row(db_session, account_id, "frank@corp.com")
    assert row.current_score == 12.0
    assert row.recent_signals[0]["type"] == "SIMULATION_PHISHING_CLICKED"


# --------------------------------------------------------------------------------------
# record_event_batch_signals
# --------------------------------------------------------------------------------------


def _auth_fail_events(actor: str, n: int, ts: datetime) -> list[ActivityEvent]:
    return [
        ActivityEvent(timestamp=ts, actor=actor, action=EventAction.AUTH_FAIL, outcome="failure")
        for _ in range(n)
    ]


def test_auth_category_produces_auth_anomaly_signal(db_session, test_account, monkeypatch):
    monkeypatch.setattr(settings, "threat_level_points_auth_anomaly", 8.0)
    account_id = test_account.account.id
    actor = "gina@corp.com"
    baseline = empty_baseline(actor)
    contribution = WeakSignalContribution(categories=frozenset({"auth"}), raw_points=3.0, chronic_points=0.0)
    batch_events = _auth_fail_events(actor, 2, _BASE)

    record_event_batch_signals(db_session, account_id, actor, batch_events, baseline, contribution, [], _BASE)
    db_session.commit()
    row = _row(db_session, account_id, actor)
    assert row.current_score == 8.0
    assert row.recent_signals[0]["type"] == "AUTH_ANOMALY"


def test_new_location_produces_auth_anomaly_signal(db_session, test_account, monkeypatch):
    monkeypatch.setattr(settings, "threat_level_min_events_for_location_check", 5)
    monkeypatch.setattr(settings, "threat_level_points_auth_anomaly", 8.0)
    account_id = test_account.account.id
    actor = "helen@corp.com"

    baseline = empty_baseline(actor)
    for i in range(6):
        baseline = update_baseline(
            baseline,
            [
                ActivityEvent(
                    timestamp=_BASE + timedelta(days=i), actor=actor, action=EventAction.LOGIN,
                    outcome="success", geo=GeoLocation(country="US"),
                )
            ],
        )
    assert baseline.event_count >= 5

    contribution = WeakSignalContribution()
    new_location_event = [
        ActivityEvent(
            timestamp=_BASE + timedelta(days=10), actor=actor, action=EventAction.LOGIN,
            outcome="success", geo=GeoLocation(country="RU"),
        )
    ]

    record_event_batch_signals(
        db_session, account_id, actor, new_location_event, baseline, contribution, [], _BASE
    )
    db_session.commit()
    row = _row(db_session, account_id, actor)
    assert row is not None
    assert row.recent_signals[0]["type"] == "AUTH_ANOMALY"
    assert "location" in row.recent_signals[0]["description"]


def test_new_location_disabled_under_cold_start(db_session, test_account, monkeypatch):
    monkeypatch.setattr(settings, "threat_level_min_events_for_location_check", 10)
    account_id = test_account.account.id
    actor = "ian@corp.com"
    baseline = empty_baseline(actor)  # event_count == 0

    events = [
        ActivityEvent(
            timestamp=_BASE, actor=actor, action=EventAction.LOGIN, outcome="success",
            geo=GeoLocation(country="RU"),
        )
    ]
    record_event_batch_signals(db_session, account_id, actor, events, baseline, WeakSignalContribution(), [], _BASE)
    db_session.commit()
    assert _row(db_session, account_id, actor) is None


def test_sensitive_category_produces_first_time_sensitive_access_signal(db_session, test_account, monkeypatch):
    monkeypatch.setattr(settings, "threat_level_points_sensitive_access_cold_start", 10.0)
    account_id = test_account.account.id
    actor = "jack@corp.com"
    baseline = empty_baseline(actor)
    contribution = WeakSignalContribution(categories=frozenset({"sensitive"}), raw_points=5.0, chronic_points=0.0)

    record_event_batch_signals(db_session, account_id, actor, [], baseline, contribution, [], _BASE)
    db_session.commit()
    row = _row(db_session, account_id, actor)
    assert row.current_score == 10.0
    assert row.recent_signals[0]["type"] == "FIRST_TIME_SENSITIVE_ACCESS"


def test_real_sensitive_finding_produces_damped_signal(db_session, test_account, monkeypatch):
    monkeypatch.setattr(settings, "threat_level_finding_weight", 0.3)
    account_id = test_account.account.id
    actor = "karen@corp.com"
    baseline = empty_baseline(actor)
    finding = Finding(
        id="SENSITIVE_RESOURCE_FIRST_ACCESS", category="insider_threat", title="t", description="d",
        severity=Severity.MEDIUM, points=30.0, evidence_event_ids=[],
    )

    record_event_batch_signals(db_session, account_id, actor, [], baseline, WeakSignalContribution(), [finding], _BASE)
    db_session.commit()
    row = _row(db_session, account_id, actor)
    assert row.current_score == 9.0  # 30 * 0.3


def test_transfer_category_produces_small_unfamiliar_transfer_signal(db_session, test_account, monkeypatch):
    monkeypatch.setattr(settings, "threat_level_points_small_transfer", 8.0)
    account_id = test_account.account.id
    actor = "liam@corp.com"
    baseline = empty_baseline(actor)
    contribution = WeakSignalContribution(categories=frozenset({"transfer"}), raw_points=3.0, chronic_points=0.0)

    record_event_batch_signals(db_session, account_id, actor, [], baseline, contribution, [], _BASE)
    db_session.commit()
    row = _row(db_session, account_id, actor)
    assert row.current_score == 8.0
    assert row.recent_signals[0]["type"] == "SMALL_UNFAMILIAR_TRANSFER"


def test_two_co_occurring_categories_also_produce_accumulator_signal(db_session, test_account, monkeypatch):
    monkeypatch.setattr(settings, "threat_level_points_auth_anomaly", 8.0)
    monkeypatch.setattr(settings, "threat_level_points_small_transfer", 8.0)
    monkeypatch.setattr(settings, "threat_level_points_accumulator_signal", 15.0)
    account_id = test_account.account.id
    actor = "mia@corp.com"
    baseline = empty_baseline(actor)
    contribution = WeakSignalContribution(
        categories=frozenset({"auth", "transfer"}), raw_points=6.0, chronic_points=6.0
    )

    record_event_batch_signals(db_session, account_id, actor, [], baseline, contribution, [], _BASE)
    db_session.commit()
    row = _row(db_session, account_id, actor)
    types = {s["type"] for s in row.recent_signals}
    assert types == {"AUTH_ANOMALY", "SMALL_UNFAMILIAR_TRANSFER", "STAGE_D_ACCUMULATOR_SIGNAL"}


def test_low_signal_finding_firing_produces_accumulator_signal_even_alone(db_session, test_account):
    account_id = test_account.account.id
    actor = "noah@corp.com"
    baseline = empty_baseline(actor)
    finding = Finding(
        id="LOW_SIGNAL_PATTERN_ACCUMULATION", category="insider_threat", title="t", description="d",
        severity=Severity.MEDIUM, points=20.0, evidence_event_ids=[],
    )

    record_event_batch_signals(db_session, account_id, actor, [], baseline, WeakSignalContribution(), [finding], _BASE)
    db_session.commit()
    row = _row(db_session, account_id, actor)
    assert row.recent_signals[0]["type"] == "STAGE_D_ACCUMULATOR_SIGNAL"


def test_no_signals_creates_no_row(db_session, test_account):
    account_id = test_account.account.id
    actor = "olive@corp.com"
    baseline = empty_baseline(actor)
    record_event_batch_signals(db_session, account_id, actor, [], baseline, WeakSignalContribution(), [], _BASE)
    db_session.commit()
    assert _row(db_session, account_id, actor) is None
