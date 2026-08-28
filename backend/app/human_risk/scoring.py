"""Pure per-employee phishing-simulation risk scoring (M9 Stage 2) — no DB/I/O here, mirrors
every other pure aggregation module in this codebase (app.dashboard.aggregation,
app.remediation.targets, app.autonomy.policy, ...).

Point-additive with a clamp, not a percentage/rate model: each failed campaign contributes a
fixed number of points regardless of how many clean campaigns the same person has also had,
and reporting subtracts fixed credit — deliberately simple and monotonic ("more failures raise
it, reporting lowers it") rather than statistically normalized. No time decay in Stage 2.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

CLICK_PENALTY = 20
SUBMIT_PENALTY = 40
REPORT_CREDIT = 15
# Additional credit on top of REPORT_CREDIT for a fast report (25 total) — see
# app.core.config.settings.human_risk_fast_report_window_minutes for what counts as fast.
REPORT_FAST_BONUS_CREDIT = 10
SCORE_MIN = 0
SCORE_MAX = 100


@dataclass(frozen=True)
class RecipientCampaignOutcome:
    """One campaign's outcome for one recipient — denormalized (template_name carried
    directly rather than looked up from app.simulation.templates.TEMPLATES here), same
    pattern as app.remediation.targets.TargetCaseRow carrying indicator titles directly."""

    campaign_id: str
    template_id: str
    template_name: str
    department: str | None
    sent_at: datetime | None
    clicked_at: datetime | None
    submitted_at: datetime | None
    reported_at: datetime | None


@dataclass(frozen=True)
class RecipientSimulationHistory:
    email: str
    outcomes: list[RecipientCampaignOutcome]


def _is_fast_report(outcome: RecipientCampaignOutcome, *, fast_report_window_minutes: int) -> bool:
    if outcome.reported_at is None or outcome.sent_at is None:
        return False
    return (outcome.reported_at - outcome.sent_at) <= timedelta(minutes=fast_report_window_minutes)


def compute_risk_score(
    history: RecipientSimulationHistory, *, fast_report_window_minutes: int
) -> int:
    """Per-campaign-outcome, boolean-severity scoring (not raw click/submit counts) — a
    recipient re-clicking the same simulated link five times out of curiosity is one
    failure, not five; a submit always outranks a bare click for that same outcome (never
    both). Reporting is scored independently of click/submit and can reduce the running
    total below what the failures alone produced, including into negative territory before
    the final clamp — the clamp is applied once, to the summed total, not per term."""
    raw = 0
    for outcome in history.outcomes:
        if outcome.submitted_at is not None:
            raw += SUBMIT_PENALTY
        elif outcome.clicked_at is not None:
            raw += CLICK_PENALTY

        if outcome.reported_at is not None:
            raw -= REPORT_CREDIT
            if _is_fast_report(outcome, fast_report_window_minutes=fast_report_window_minutes):
                raw -= REPORT_FAST_BONUS_CREDIT

    return max(SCORE_MIN, min(SCORE_MAX, raw))
