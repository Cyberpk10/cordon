"""Required property: the risk score must rise with repeated failures. Table-driven against
the pure app.human_risk.scoring.compute_risk_score — no DB, fully offline.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.human_risk.scoring import (
    RecipientCampaignOutcome,
    RecipientSimulationHistory,
    compute_risk_score,
)

FAST_WINDOW = 60
SENT = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _outcome(
    *, clicked: bool = False, submitted: bool = False, reported_at: datetime | None = None
) -> RecipientCampaignOutcome:
    return RecipientCampaignOutcome(
        campaign_id="c1",
        template_id="it_password_reset",
        template_name="IT: password expiring today",
        department=None,
        sent_at=SENT,
        clicked_at=SENT if clicked else None,
        submitted_at=SENT if submitted else None,
        reported_at=reported_at,
    )


def test_no_interactions_scores_zero():
    history = RecipientSimulationHistory(email="a@corp.example", outcomes=[])
    assert compute_risk_score(history, fast_report_window_minutes=FAST_WINDOW) == 0


def test_single_click_scores_twenty():
    history = RecipientSimulationHistory(email="a@corp.example", outcomes=[_outcome(clicked=True)])
    assert compute_risk_score(history, fast_report_window_minutes=FAST_WINDOW) == 20


def test_single_submit_scores_forty():
    history = RecipientSimulationHistory(email="a@corp.example", outcomes=[_outcome(submitted=True)])
    assert compute_risk_score(history, fast_report_window_minutes=FAST_WINDOW) == 40


def test_submit_outranks_click_for_the_same_outcome():
    """A submit implies a click happened too, but must not double-count."""
    history = RecipientSimulationHistory(
        email="a@corp.example", outcomes=[_outcome(clicked=True, submitted=True)]
    )
    assert compute_risk_score(history, fast_report_window_minutes=FAST_WINDOW) == 40


@pytest.mark.parametrize(
    "outcome_count,expected",
    [(1, 20), (2, 40), (3, 60)],
)
def test_repeated_click_failures_raise_the_score_monotonically(outcome_count, expected):
    history = RecipientSimulationHistory(
        email="a@corp.example", outcomes=[_outcome(clicked=True) for _ in range(outcome_count)]
    )
    assert compute_risk_score(history, fast_report_window_minutes=FAST_WINDOW) == expected


def test_score_clamps_at_one_hundred():
    history = RecipientSimulationHistory(
        email="a@corp.example", outcomes=[_outcome(submitted=True) for _ in range(5)]
    )
    assert compute_risk_score(history, fast_report_window_minutes=FAST_WINDOW) == 100


def test_slow_report_after_submit_gives_partial_credit():
    slow_report = SENT + timedelta(hours=5)
    history = RecipientSimulationHistory(
        email="a@corp.example",
        outcomes=[_outcome(submitted=True, reported_at=slow_report)],
    )
    assert compute_risk_score(history, fast_report_window_minutes=FAST_WINDOW) == 40 - 15


def test_fast_report_after_submit_gives_larger_credit():
    fast_report = SENT + timedelta(minutes=30)
    history = RecipientSimulationHistory(
        email="a@corp.example",
        outcomes=[_outcome(submitted=True, reported_at=fast_report)],
    )
    assert compute_risk_score(history, fast_report_window_minutes=FAST_WINDOW) == 40 - 15 - 10


def test_report_with_no_prior_failure_only_lowers_and_clamps_to_zero():
    history = RecipientSimulationHistory(
        email="a@corp.example",
        outcomes=[_outcome(reported_at=SENT + timedelta(minutes=5))],
    )
    assert compute_risk_score(history, fast_report_window_minutes=FAST_WINDOW) == 0


def test_report_with_no_sent_at_never_counts_as_fast():
    outcome = RecipientCampaignOutcome(
        campaign_id="c1",
        template_id="it_password_reset",
        template_name="IT: password expiring today",
        department=None,
        sent_at=None,
        clicked_at=None,
        submitted_at=SENT,
        reported_at=SENT + timedelta(minutes=1),
    )
    history = RecipientSimulationHistory(email="a@corp.example", outcomes=[outcome])
    # Only the slow (non-fast) report credit applies since sent_at is missing.
    assert compute_risk_score(history, fast_report_window_minutes=FAST_WINDOW) == 40 - 15
