"""The Human Risk view (M9 Stage 2) — read-only reporting over phishing-simulation results:
riskiest employees, click-rate trend, most-effective lures, and department breakdown, plus
the stored per-employee training recommendations. Nothing is mutated here (the training
recommendation upsert already happens inline in app.api.routes.simulation.track, at the
moment an employee actually fails a campaign) — `get_current_user` only, same read-level
auth as GET /api/dashboard/summary and GET /api/targets; no admin gate, since nothing here
changes state.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.auth.dependencies import get_current_user
from app.core.config import settings
from app.core.time import to_naive_utc
from app.db.models import SimulationCampaign, SimulationRecipient, SimulationTrainingRecommendation, User
from app.db.session import get_db
from app.human_risk.reporting import (
    click_rate_over_time,
    department_breakdown,
    lure_effectiveness,
    riskiest_users,
)
from app.human_risk.scoring import RecipientCampaignOutcome, RecipientSimulationHistory
from app.models.schemas import (
    ClickRatePeriodResponse,
    DepartmentBreakdownResponse,
    HumanRiskSummaryResponse,
    LureEffectivenessResponse,
    RiskiestUserResponse,
    SimulationTrainingRecommendationResponse,
    SimulationTrainingRecommendationsListResponse,
)
from app.simulation.templates import TEMPLATES

router = APIRouter(prefix="/api/human-risk", tags=["human-risk"])

DEFAULT_PERIOD_DAYS = 30


def _resolve_period(date_from: datetime | None, date_to: datetime | None) -> tuple[datetime, datetime]:
    period_end = date_to or datetime.utcnow()
    period_start = date_from or (period_end - timedelta(days=DEFAULT_PERIOD_DAYS))
    return period_start, period_end


def _sent_recipients_in_period(
    db: Session, account_id: uuid.UUID, period_start: datetime, period_end: datetime
) -> list[tuple[SimulationRecipient, SimulationCampaign]]:
    return (
        db.query(SimulationRecipient, SimulationCampaign)
        .join(SimulationCampaign, SimulationRecipient.campaign_id == SimulationCampaign.id)
        .filter(
            SimulationRecipient.account_id == account_id,
            SimulationCampaign.sent_at.isnot(None),
            SimulationCampaign.sent_at >= period_start,
            SimulationCampaign.sent_at <= period_end,
        )
        .all()
    )


def _naive(value: datetime | None) -> datetime | None:
    """See app.core.time.to_naive_utc — SQLite round-trips DateTime(timezone=True) columns
    as naive while Postgres returns them aware; normalize before any arithmetic/comparison."""
    return to_naive_utc(value) if value is not None else None


def _to_outcome(recipient: SimulationRecipient, campaign: SimulationCampaign) -> RecipientCampaignOutcome:
    return RecipientCampaignOutcome(
        campaign_id=str(campaign.id),
        template_id=campaign.template_id,
        template_name=TEMPLATES[campaign.template_id].name,
        department=recipient.department,
        sent_at=_naive(campaign.sent_at),
        clicked_at=_naive(recipient.clicked_at),
        submitted_at=_naive(recipient.submitted_at),
        reported_at=_naive(recipient.reported_at),
    )


def _group_by_email(
    rows: list[tuple[SimulationRecipient, SimulationCampaign]],
) -> list[RecipientSimulationHistory]:
    by_email: dict[str, list[RecipientCampaignOutcome]] = {}
    for recipient, campaign in rows:
        by_email.setdefault(recipient.email, []).append(_to_outcome(recipient, campaign))
    return [RecipientSimulationHistory(email=email, outcomes=group) for email, group in by_email.items()]


@router.get("/summary", response_model=HumanRiskSummaryResponse)
async def get_human_risk_summary(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    date_from: datetime | None = None,
    date_to: datetime | None = None,
) -> HumanRiskSummaryResponse:
    period_start, period_end = _resolve_period(date_from, date_to)

    rows = _sent_recipients_in_period(db, current_user.account_id, period_start, period_end)
    outcomes = [_to_outcome(recipient, campaign) for recipient, campaign in rows]
    histories = _group_by_email(rows)
    fast_window = settings.human_risk_fast_report_window_minutes

    return HumanRiskSummaryResponse(
        period_start=period_start,
        period_end=period_end,
        riskiest_users=[
            RiskiestUserResponse(
                email=r.email,
                department=r.department,
                risk_score=r.risk_score,
                click_count=r.click_count,
                submit_count=r.submit_count,
                report_count=r.report_count,
                last_failure_at=r.last_failure_at,
            )
            for r in riskiest_users(histories, fast_report_window_minutes=fast_window)
        ],
        click_rate_over_time=[
            ClickRatePeriodResponse(
                period_start=row.period_start,
                period_end=row.period_end,
                sent_count=row.sent_count,
                click_count=row.click_count,
                submit_count=row.submit_count,
                report_count=row.report_count,
                click_rate=row.click_rate,
                submit_rate=row.submit_rate,
            )
            for row in click_rate_over_time(outcomes, period_start=period_start, period_end=period_end)
        ],
        lure_effectiveness=[
            LureEffectivenessResponse(
                template_id=row.template_id,
                template_name=row.template_name,
                sent_count=row.sent_count,
                click_count=row.click_count,
                submit_count=row.submit_count,
                click_rate=row.click_rate,
                submit_rate=row.submit_rate,
            )
            for row in lure_effectiveness(outcomes)
        ],
        department_breakdown=[
            DepartmentBreakdownResponse(
                department=row.department,
                employees_tested=row.employees_tested,
                click_count=row.click_count,
                submit_count=row.submit_count,
                report_count=row.report_count,
                avg_risk_score=row.avg_risk_score,
            )
            for row in department_breakdown(histories, fast_report_window_minutes=fast_window)
        ],
        generated_at=datetime.now(),
    )


@router.get("/recommendations", response_model=SimulationTrainingRecommendationsListResponse)
async def list_training_recommendations(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SimulationTrainingRecommendationsListResponse:
    """Pure read — unlike GET /api/targets, this never recomputes/upserts anything itself;
    the stored rows are already kept current inline by
    app.api.routes.simulation._upsert_training_recommendation whenever a click/submit event
    fires."""
    rows = (
        db.query(SimulationTrainingRecommendation)
        .filter(SimulationTrainingRecommendation.account_id == current_user.account_id)
        .order_by(SimulationTrainingRecommendation.risk_score.desc())
        .all()
    )
    items = [
        SimulationTrainingRecommendationResponse(
            recipient=row.recipient,
            template_id=row.template_id,
            template_name=row.template_name,
            risk_score=row.risk_score,
            recommendation=row.recommendation,
            first_flagged_at=row.first_flagged_at,
            updated_at=row.updated_at,
        )
        for row in rows
    ]
    return SimulationTrainingRecommendationsListResponse(items=items, total=len(items))
