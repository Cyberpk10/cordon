from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.human_risk.audit_evidence import (
    SimulationCampaignRow,
    SimulationRecipientRow,
    human_risk_evidence_for_framework,
)

DAY1 = datetime(2026, 1, 1, tzinfo=timezone.utc)


def test_zero_campaigns_gives_zeroed_evidence():
    evidence = human_risk_evidence_for_framework(campaigns=[], recipients=[], trained_recipient_emails=set())
    assert evidence.campaigns_run == 0
    assert evidence.distinct_employees_tested == 0
    assert evidence.distinct_employees_trained == 0
    assert evidence.sample_campaign_ids == []


def test_counts_distinct_employees_and_campaigns():
    campaigns = [
        SimulationCampaignRow(id="c1", sent_at=DAY1, template_id="it_password_reset"),
        SimulationCampaignRow(id="c2", sent_at=DAY1 + timedelta(days=1), template_id="hr_benefits_deadline"),
    ]
    recipients = [
        SimulationRecipientRow(campaign_id="c1", email="a@corp.example", clicked_at=DAY1, submitted_at=None, reported_at=None),
        SimulationRecipientRow(campaign_id="c1", email="b@corp.example", clicked_at=None, submitted_at=None, reported_at=None),
        SimulationRecipientRow(campaign_id="c2", email="a@corp.example", clicked_at=None, submitted_at=None, reported_at=None),
    ]
    evidence = human_risk_evidence_for_framework(
        campaigns=campaigns,
        recipients=recipients,
        trained_recipient_emails={"a@corp.example"},
    )
    assert evidence.campaigns_run == 2
    assert evidence.distinct_employees_tested == 2
    assert evidence.distinct_employees_trained == 1


def test_sample_campaign_ids_sorted_by_recency_and_capped():
    campaigns = [
        SimulationCampaignRow(id=f"c{i}", sent_at=DAY1 + timedelta(days=i), template_id="it_password_reset")
        for i in range(8)
    ]
    evidence = human_risk_evidence_for_framework(
        campaigns=campaigns, recipients=[], trained_recipient_emails=set(), sample_size=5
    )
    assert len(evidence.sample_campaign_ids) == 5
    assert evidence.sample_campaign_ids == ["c7", "c6", "c5", "c4", "c3"]
