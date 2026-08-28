"""Pure training-recommendation decision logic (M9 Stage 2) — no DB/I/O here, mirrors
app.human_risk.scoring and every other pure decision module in this codebase.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.human_risk.scoring import RecipientSimulationHistory, compute_risk_score


@dataclass(frozen=True)
class TrainingRecommendationDecision:
    should_upsert: bool
    risk_score: int
    template_id: str | None
    template_name: str | None
    recommendation: str | None


def decide_training_recommendation(
    history: RecipientSimulationHistory, *, fast_report_window_minutes: int
) -> TrainingRecommendationDecision:
    """Only click/submit outcomes count as a "failure" — a report-only history never
    triggers a recommendation, since reporting is the opposite of falling for a lure.
    Targets the MOST RECENT failure's template (by sent_at), not the most frequent one —
    the recommendation is meant to prompt a timely, specific follow-up ("you just fell for
    an IT-themed lure"), not a lifetime tally."""
    risk_score = compute_risk_score(history, fast_report_window_minutes=fast_report_window_minutes)

    failures = [
        o for o in history.outcomes if o.clicked_at is not None or o.submitted_at is not None
    ]
    if not failures:
        return TrainingRecommendationDecision(
            should_upsert=False,
            risk_score=risk_score,
            template_id=None,
            template_name=None,
            recommendation=None,
        )

    latest = max(failures, key=lambda o: o.sent_at or o.clicked_at or o.submitted_at)
    verb = "submitted the fake form on" if latest.submitted_at is not None else "clicked the link in"
    recommendation = (
        f'{history.email} most recently {verb} the "{latest.template_name}" phishing-'
        f"simulation email. Current human-risk score: {risk_score}/100. Recommend targeted "
        f'micro-training on recognizing "{latest.template_name}"-style lures.'
    )
    return TrainingRecommendationDecision(
        should_upsert=True,
        risk_score=risk_score,
        template_id=latest.template_id,
        template_name=latest.template_name,
        recommendation=recommendation,
    )
