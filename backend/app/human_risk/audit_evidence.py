"""Pure evidence-aggregation math for feeding phishing-simulation results into Audit Mode
(M9 Stage 2) — no DB here, plain dataclasses in, plain dataclasses out. Mirrors
app/audit/aggregation.py's separation from route/DB wiring, but is intentionally a separate,
parallel evidence source rather than an extension of `evidence_for_framework`: a simulation
campaign has no Verdict (Safe/Suspicious/Malicious) the way a Case does, so fabricating a
fake CaseRow/CaseRef for it would misrepresent what happened to an auditor reading the
evidence pack.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

DEFAULT_SAMPLE_SIZE = 5


@dataclass(frozen=True)
class SimulationCampaignRow:
    id: str
    sent_at: datetime | None
    template_id: str


@dataclass(frozen=True)
class SimulationRecipientRow:
    campaign_id: str
    email: str
    clicked_at: datetime | None
    submitted_at: datetime | None
    reported_at: datetime | None


@dataclass(frozen=True)
class HumanRiskControlEvidence:
    campaigns_run: int
    distinct_employees_tested: int
    distinct_employees_trained: int
    sample_campaign_ids: list[str]


def human_risk_evidence_for_framework(
    *,
    campaigns: list[SimulationCampaignRow],
    recipients: list[SimulationRecipientRow],
    trained_recipient_emails: set[str],
    sample_size: int = DEFAULT_SAMPLE_SIZE,
) -> HumanRiskControlEvidence:
    """One evidence object, shared across every control_id in
    HUMAN_RISK_CONTROL_IDS[framework_key] for a given framework — human-risk evidence isn't
    per-control granular the way case/indicator evidence is, since there's only one
    training-awareness signal in Stage 2, not one per control."""
    samples = sorted(campaigns, key=lambda c: c.sent_at or datetime.min, reverse=True)[:sample_size]
    return HumanRiskControlEvidence(
        campaigns_run=len(campaigns),
        distinct_employees_tested=len({r.email for r in recipients}),
        distinct_employees_trained=len(trained_recipient_emails),
        sample_campaign_ids=[c.id for c in samples],
    )
