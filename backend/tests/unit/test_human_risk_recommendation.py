from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.human_risk.recommendation import decide_training_recommendation
from app.human_risk.scoring import RecipientCampaignOutcome, RecipientSimulationHistory

FAST_WINDOW = 60
DAY1 = datetime(2026, 1, 1, tzinfo=timezone.utc)
DAY2 = DAY1 + timedelta(days=1)


def _outcome(
    *, campaign_id, template_id, template_name, sent_at, clicked=False, submitted=False, reported_at=None
) -> RecipientCampaignOutcome:
    return RecipientCampaignOutcome(
        campaign_id=campaign_id,
        template_id=template_id,
        template_name=template_name,
        department=None,
        sent_at=sent_at,
        clicked_at=sent_at if clicked else None,
        submitted_at=sent_at if submitted else None,
        reported_at=reported_at,
    )


def test_no_failures_never_upserts():
    history = RecipientSimulationHistory(email="a@corp.example", outcomes=[])
    decision = decide_training_recommendation(history, fast_report_window_minutes=FAST_WINDOW)
    assert decision.should_upsert is False
    assert decision.template_id is None


def test_report_only_history_never_upserts():
    history = RecipientSimulationHistory(
        email="a@corp.example",
        outcomes=[
            _outcome(
                campaign_id="c1", template_id="it_password_reset", template_name="IT lure",
                sent_at=DAY1, reported_at=DAY1,
            )
        ],
    )
    decision = decide_training_recommendation(history, fast_report_window_minutes=FAST_WINDOW)
    assert decision.should_upsert is False


def test_single_failure_references_that_template():
    history = RecipientSimulationHistory(
        email="a@corp.example",
        outcomes=[
            _outcome(
                campaign_id="c1", template_id="it_password_reset", template_name="IT lure",
                sent_at=DAY1, clicked=True,
            )
        ],
    )
    decision = decide_training_recommendation(history, fast_report_window_minutes=FAST_WINDOW)
    assert decision.should_upsert is True
    assert decision.template_id == "it_password_reset"
    assert "IT lure" in decision.recommendation
    assert decision.risk_score == 20


def test_targets_most_recent_failure_regardless_of_input_order():
    """Required property: the recommendation matches the exact lure type most recently
    fallen for, even when the older failure is listed last in the input."""
    older = _outcome(
        campaign_id="c2", template_id="hr_benefits_deadline", template_name="HR lure",
        sent_at=DAY1, clicked=True,
    )
    newer = _outcome(
        campaign_id="c1", template_id="it_password_reset", template_name="IT lure",
        sent_at=DAY2, submitted=True,
    )
    history = RecipientSimulationHistory(email="a@corp.example", outcomes=[older, newer])
    decision = decide_training_recommendation(history, fast_report_window_minutes=FAST_WINDOW)
    assert decision.template_id == "it_password_reset"

    # Order-independence: same result with the list reversed.
    reversed_history = RecipientSimulationHistory(email="a@corp.example", outcomes=[newer, older])
    reversed_decision = decide_training_recommendation(
        reversed_history, fast_report_window_minutes=FAST_WINDOW
    )
    assert reversed_decision.template_id == "it_password_reset"


def test_recommendation_text_names_the_lure_and_current_score():
    history = RecipientSimulationHistory(
        email="bob@corp.example",
        outcomes=[
            _outcome(
                campaign_id="c1", template_id="shared_document_notice", template_name="Doc lure",
                sent_at=DAY1, submitted=True,
            )
        ],
    )
    decision = decide_training_recommendation(history, fast_report_window_minutes=FAST_WINDOW)
    assert "bob@corp.example" in decision.recommendation
    assert "Doc lure" in decision.recommendation
    assert "40" in decision.recommendation
