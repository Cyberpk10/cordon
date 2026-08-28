from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.human_risk.reporting import (
    UNSPECIFIED_DEPARTMENT,
    click_rate_over_time,
    department_breakdown,
    lure_effectiveness,
    riskiest_users,
)
from app.human_risk.scoring import RecipientCampaignOutcome, RecipientSimulationHistory

FAST_WINDOW = 60
DAY1 = datetime(2026, 1, 1, tzinfo=timezone.utc)
DAY2 = DAY1 + timedelta(days=10)


def _outcome(**overrides) -> RecipientCampaignOutcome:
    base = dict(
        campaign_id="c1",
        template_id="it_password_reset",
        template_name="IT lure",
        department=None,
        sent_at=DAY1,
        clicked_at=None,
        submitted_at=None,
        reported_at=None,
    )
    base.update(overrides)
    return RecipientCampaignOutcome(**base)


def test_riskiest_users_sorted_descending_by_score():
    histories = [
        RecipientSimulationHistory(email="low@corp.example", outcomes=[_outcome(clicked_at=DAY1)]),
        RecipientSimulationHistory(email="high@corp.example", outcomes=[_outcome(submitted_at=DAY1)]),
    ]
    rows = riskiest_users(histories, fast_report_window_minutes=FAST_WINDOW)
    assert [r.email for r in rows] == ["high@corp.example", "low@corp.example"]


def test_riskiest_users_respects_top_n():
    histories = [
        RecipientSimulationHistory(email=f"u{i}@corp.example", outcomes=[_outcome(clicked_at=DAY1)])
        for i in range(5)
    ]
    rows = riskiest_users(histories, fast_report_window_minutes=FAST_WINDOW, top_n=2)
    assert len(rows) == 2


def test_lure_effectiveness_rate_math():
    outcomes = [
        _outcome(template_id="a", template_name="A", clicked_at=DAY1),
        _outcome(template_id="a", template_name="A", clicked_at=None),
        _outcome(template_id="a", template_name="A", clicked_at=DAY1, submitted_at=DAY1),
        _outcome(template_id="b", template_name="B", clicked_at=None),
    ]
    rows = {r.template_id: r for r in lure_effectiveness(outcomes)}

    assert rows["a"].sent_count == 3
    assert rows["a"].click_count == 2
    assert rows["a"].submit_count == 1
    assert rows["a"].click_rate == 2 / 3
    assert rows["b"].click_rate == 0.0


def test_lure_effectiveness_sorted_by_click_rate_descending():
    outcomes = [
        _outcome(template_id="low", template_name="Low", clicked_at=None),
        _outcome(template_id="high", template_name="High", clicked_at=DAY1),
    ]
    rows = lure_effectiveness(outcomes)
    assert [r.template_id for r in rows] == ["high", "low"]


def test_department_breakdown_unspecified_bucket_for_no_department():
    histories = [
        RecipientSimulationHistory(email="a@corp.example", outcomes=[_outcome(department=None)]),
    ]
    rows = department_breakdown(histories, fast_report_window_minutes=FAST_WINDOW)
    assert rows[0].department == UNSPECIFIED_DEPARTMENT
    assert rows[0].employees_tested == 1


def test_department_breakdown_uses_most_recent_non_null_department():
    outcomes = [
        _outcome(sent_at=DAY1, department="Sales"),
        _outcome(sent_at=DAY2, department="Engineering"),
    ]
    histories = [RecipientSimulationHistory(email="a@corp.example", outcomes=outcomes)]
    rows = department_breakdown(histories, fast_report_window_minutes=FAST_WINDOW)
    assert rows[0].department == "Engineering"


def test_department_breakdown_averages_risk_score_within_department():
    histories = [
        RecipientSimulationHistory(
            email="a@corp.example", outcomes=[_outcome(department="Sales", clicked_at=DAY1)]
        ),
        RecipientSimulationHistory(
            email="b@corp.example", outcomes=[_outcome(department="Sales", submitted_at=DAY1)]
        ),
    ]
    rows = department_breakdown(histories, fast_report_window_minutes=FAST_WINDOW)
    sales = next(r for r in rows if r.department == "Sales")
    assert sales.employees_tested == 2
    assert sales.avg_risk_score == (20 + 40) / 2


def test_click_rate_over_time_buckets_by_week_and_skips_empty_buckets():
    period_start = DAY1
    period_end = DAY1 + timedelta(days=21)
    outcomes = [
        _outcome(sent_at=DAY1, clicked_at=DAY1),
        _outcome(sent_at=DAY1 + timedelta(days=1), clicked_at=None),
        _outcome(sent_at=DAY1 + timedelta(days=15), clicked_at=DAY1),
    ]
    rows = click_rate_over_time(
        outcomes, period_start=period_start, period_end=period_end, bucket_days=7
    )
    # Only 2 non-empty weekly buckets (week 0 and week 2) — week 1 has no sent outcomes.
    assert len(rows) == 2
    assert rows[0].sent_count == 2
    assert rows[0].click_count == 1
    assert rows[1].sent_count == 1
    assert rows[1].click_count == 1


def test_click_rate_over_time_skips_outcomes_with_no_sent_at():
    outcomes = [_outcome(sent_at=None, clicked_at=None)]
    rows = click_rate_over_time(outcomes, period_start=DAY1, period_end=DAY2)
    assert rows == []
