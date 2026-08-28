"""Pure aggregation math for the Human Risk view (M9 Stage 2) — no DB/SQLAlchemy here, just
plain dataclasses in, plain dataclasses out. Mirrors app/dashboard/aggregation.py's
separation from route/DB wiring (app/api/routes/human_risk.py).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from app.human_risk.scoring import (
    RecipientCampaignOutcome,
    RecipientSimulationHistory,
    compute_risk_score,
)

UNSPECIFIED_DEPARTMENT = "Unspecified"


def _resolve_department(history: RecipientSimulationHistory) -> str:
    """Most recent non-null department supplied for this email, across every campaign it
    appears in — see app.db.models.SimulationRecipient's docstring for why this is a
    documented simplification (no employee directory exists in this codebase)."""
    dated = [
        (o.sent_at, o.department)
        for o in history.outcomes
        if o.department is not None and o.sent_at is not None
    ]
    if not dated:
        return UNSPECIFIED_DEPARTMENT
    return max(dated, key=lambda pair: pair[0])[1]


@dataclass(frozen=True)
class RiskiestUserRow:
    email: str
    department: str
    risk_score: int
    click_count: int
    submit_count: int
    report_count: int
    last_failure_at: datetime | None


def riskiest_users(
    histories: list[RecipientSimulationHistory],
    *,
    fast_report_window_minutes: int,
    top_n: int = 20,
) -> list[RiskiestUserRow]:
    rows: list[RiskiestUserRow] = []
    for history in histories:
        click_count = sum(1 for o in history.outcomes if o.clicked_at is not None)
        submit_count = sum(1 for o in history.outcomes if o.submitted_at is not None)
        report_count = sum(1 for o in history.outcomes if o.reported_at is not None)
        failure_times = [
            o.submitted_at or o.clicked_at
            for o in history.outcomes
            if o.clicked_at is not None or o.submitted_at is not None
        ]
        rows.append(
            RiskiestUserRow(
                email=history.email,
                department=_resolve_department(history),
                risk_score=compute_risk_score(
                    history, fast_report_window_minutes=fast_report_window_minutes
                ),
                click_count=click_count,
                submit_count=submit_count,
                report_count=report_count,
                last_failure_at=max(failure_times) if failure_times else None,
            )
        )
    rows.sort(key=lambda r: r.risk_score, reverse=True)
    return rows[:top_n]


@dataclass(frozen=True)
class LureEffectivenessRow:
    template_id: str
    template_name: str
    sent_count: int
    click_count: int
    submit_count: int
    click_rate: float
    submit_rate: float


def lure_effectiveness(outcomes: list[RecipientCampaignOutcome]) -> list[LureEffectivenessRow]:
    """Grouped by template_id across every campaign that used it — "most effective lures"
    ranked by click_rate descending, since a click is the more common, comparable signal
    (submit_rate is usually a subset and often much sparser)."""
    by_template: dict[str, list[RecipientCampaignOutcome]] = {}
    names: dict[str, str] = {}
    for outcome in outcomes:
        by_template.setdefault(outcome.template_id, []).append(outcome)
        names.setdefault(outcome.template_id, outcome.template_name)

    rows: list[LureEffectivenessRow] = []
    for template_id, group in by_template.items():
        sent_count = len(group)
        click_count = sum(1 for o in group if o.clicked_at is not None)
        submit_count = sum(1 for o in group if o.submitted_at is not None)
        rows.append(
            LureEffectivenessRow(
                template_id=template_id,
                template_name=names[template_id],
                sent_count=sent_count,
                click_count=click_count,
                submit_count=submit_count,
                click_rate=(click_count / sent_count) if sent_count else 0.0,
                submit_rate=(submit_count / sent_count) if sent_count else 0.0,
            )
        )
    rows.sort(key=lambda r: r.click_rate, reverse=True)
    return rows


@dataclass(frozen=True)
class DepartmentBreakdownRow:
    department: str
    employees_tested: int
    click_count: int
    submit_count: int
    report_count: int
    avg_risk_score: float


def department_breakdown(
    histories: list[RecipientSimulationHistory], *, fast_report_window_minutes: int
) -> list[DepartmentBreakdownRow]:
    by_department: dict[str, list[RecipientSimulationHistory]] = {}
    for history in histories:
        by_department.setdefault(_resolve_department(history), []).append(history)

    rows: list[DepartmentBreakdownRow] = []
    for department, group in by_department.items():
        scores = [
            compute_risk_score(h, fast_report_window_minutes=fast_report_window_minutes)
            for h in group
        ]
        rows.append(
            DepartmentBreakdownRow(
                department=department,
                employees_tested=len(group),
                click_count=sum(
                    1 for h in group for o in h.outcomes if o.clicked_at is not None
                ),
                submit_count=sum(
                    1 for h in group for o in h.outcomes if o.submitted_at is not None
                ),
                report_count=sum(
                    1 for h in group for o in h.outcomes if o.reported_at is not None
                ),
                avg_risk_score=sum(scores) / len(scores) if scores else 0.0,
            )
        )
    rows.sort(key=lambda r: r.avg_risk_score, reverse=True)
    return rows


@dataclass(frozen=True)
class ClickRatePeriodRow:
    period_start: datetime
    period_end: datetime
    sent_count: int
    click_count: int
    submit_count: int
    report_count: int
    click_rate: float
    submit_rate: float


def click_rate_over_time(
    outcomes: list[RecipientCampaignOutcome],
    *,
    period_start: datetime,
    period_end: datetime,
    bucket_days: int = 7,
) -> list[ClickRatePeriodRow]:
    """Fixed-width buckets from period_start to period_end — only months/weeks with at
    least one sent outcome are included (no zero-filled gaps), mirroring
    app.dashboard.aggregation.monthly_threat_trend's convention. Outcomes with no
    `sent_at` (should not occur for already-sent campaigns) are skipped."""
    bucket_width = timedelta(days=bucket_days)
    buckets: dict[datetime, list[RecipientCampaignOutcome]] = {}

    for outcome in outcomes:
        if outcome.sent_at is None:
            continue
        offset = outcome.sent_at - period_start
        bucket_index = max(0, int(offset // bucket_width))
        bucket_start = period_start + bucket_index * bucket_width
        buckets.setdefault(bucket_start, []).append(outcome)

    rows: list[ClickRatePeriodRow] = []
    for bucket_start in sorted(buckets):
        group = buckets[bucket_start]
        sent_count = len(group)
        click_count = sum(1 for o in group if o.clicked_at is not None)
        submit_count = sum(1 for o in group if o.submitted_at is not None)
        report_count = sum(1 for o in group if o.reported_at is not None)
        rows.append(
            ClickRatePeriodRow(
                period_start=bucket_start,
                period_end=min(bucket_start + bucket_width, period_end),
                sent_count=sent_count,
                click_count=click_count,
                submit_count=submit_count,
                report_count=report_count,
                click_rate=(click_count / sent_count) if sent_count else 0.0,
                submit_rate=(submit_count / sent_count) if sent_count else 0.0,
            )
        )
    return rows
