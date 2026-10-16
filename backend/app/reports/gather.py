"""DB-touching aggregation for the Security & Compliance Report — assembles one
ReportMetrics from Cordon's own already-persisted data for an account over a period. Every
number here is a real count or a real, cited calculation already used elsewhere in the
product (verdict_counts, framework_coverage, exposure_avoided); nothing is invented or
padded, and an inactive account simply produces a metrics object full of honest zeros.

Mirrors app.investigation.gather's split: this module does the DB queries and returns plain
dataclasses, while the actual math it calls into (app.dashboard.aggregation,
app.risk_model.aggregation) stays pure and DB-free, already tested in isolation elsewhere.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from sqlalchemy.orm import Session

from app.dashboard.aggregation import CaseRow, framework_coverage, verdict_counts
from app.db.models import (
    AutonomyAction,
    Case,
    EarlyWarningAlert,
    Incident,
    SimulationCampaign,
    SimulationRecipient,
    SimulationTrainingRecommendation,
)
from app.mapping.framework_mapper import framework_display_names, total_controls_by_framework
from app.risk_model.aggregation import exposure_avoided
from app.risk_model.assumptions import risk_assumptions


@dataclass(frozen=True)
class VerdictBreakdown:
    malicious: int
    suspicious: int
    safe: int


@dataclass(frozen=True)
class ExposureByAttackType:
    attack_type: str
    count: int
    avg_loss_usd: float
    subtotal_usd: float


@dataclass(frozen=True)
class HumanRiskSummary:
    campaigns_run: int
    employees_tested: int
    employees_clicked: int
    employees_reported: int
    employees_flagged_for_training: int


@dataclass(frozen=True)
class FrameworkCoverageRow:
    framework_key: str
    framework_name: str
    total_controls: int
    covered_controls: int
    coverage_pct: float


@dataclass(frozen=True)
class ReportMetrics:
    period_start: datetime
    period_end: datetime
    emails_analyzed: int
    verdict_breakdown: VerdictBreakdown
    threats_detected: int
    threats_contained: int
    exposure_avoided_usd: float
    exposure_by_attack_type: list[ExposureByAttackType]
    incidents_detected: int
    early_warning_alerts_raised: int
    human_risk: HumanRiskSummary
    framework_coverage: list[FrameworkCoverageRow]

    @property
    def has_any_activity(self) -> bool:
        """True iff there is at least one real, period-scoped signal to report on — used
        both by the executive-summary prompt and by the PDF/JSON builders to decide whether
        to show an honest "no activity this period" note instead of empty tables."""
        return (
            self.emails_analyzed > 0
            or self.incidents_detected > 0
            or self.human_risk.campaigns_run > 0
            or self.early_warning_alerts_raised > 0
        )


def _to_case_row(case: Case) -> CaseRow:
    return CaseRow(
        id=str(case.id),
        created_at=case.created_at,
        verdict=case.verdict,
        indicators=case.indicators,
        framework_mappings=case.framework_mappings,
    )


def _cases_in_period(db: Session, account_id: UUID, period_start: datetime, period_end: datetime) -> list[Case]:
    return (
        db.query(Case)
        .filter(Case.account_id == account_id, Case.created_at >= period_start, Case.created_at <= period_end)
        .all()
    )


def _incidents_in_period(
    db: Session, account_id: UUID, period_start: datetime, period_end: datetime
) -> list[Incident]:
    return (
        db.query(Incident)
        .filter(
            Incident.account_id == account_id,
            Incident.created_at >= period_start,
            Incident.created_at <= period_end,
        )
        .all()
    )


def _threats_contained(
    db: Session, account_id: UUID, period_start: datetime, period_end: datetime
) -> int:
    """Autonomous response actions Cordon actually executed in the period (quarantine,
    block sender domain, disable session, flag for review) — status == "executed" is the
    one status that means the action really ran, not just decided or awaiting approval."""
    return (
        db.query(AutonomyAction)
        .filter(
            AutonomyAction.account_id == account_id,
            AutonomyAction.status == "executed",
            AutonomyAction.created_at >= period_start,
            AutonomyAction.created_at <= period_end,
        )
        .count()
    )


def _early_warning_alerts_raised(
    db: Session, account_id: UUID, period_start: datetime, period_end: datetime
) -> int:
    return (
        db.query(EarlyWarningAlert)
        .filter(
            EarlyWarningAlert.account_id == account_id,
            EarlyWarningAlert.created_at >= period_start,
            EarlyWarningAlert.created_at <= period_end,
        )
        .count()
    )


def _human_risk_summary(
    db: Session, account_id: UUID, period_start: datetime, period_end: datetime
) -> HumanRiskSummary:
    campaigns = (
        db.query(SimulationCampaign)
        .filter(
            SimulationCampaign.account_id == account_id,
            SimulationCampaign.sent_at.isnot(None),
            SimulationCampaign.sent_at >= period_start,
            SimulationCampaign.sent_at <= period_end,
        )
        .all()
    )
    campaign_ids = [c.id for c in campaigns]
    recipients = (
        db.query(SimulationRecipient).filter(SimulationRecipient.campaign_id.in_(campaign_ids)).all()
        if campaign_ids
        else []
    )
    trained_count = (
        db.query(SimulationTrainingRecommendation)
        .filter(
            SimulationTrainingRecommendation.account_id == account_id,
            SimulationTrainingRecommendation.updated_at >= period_start,
            SimulationTrainingRecommendation.updated_at <= period_end,
        )
        .count()
    )

    return HumanRiskSummary(
        campaigns_run=len(campaigns),
        employees_tested=len({r.email for r in recipients}),
        employees_clicked=len({r.email for r in recipients if r.clicked_at is not None}),
        employees_reported=len({r.email for r in recipients if r.reported_at is not None}),
        employees_flagged_for_training=trained_count,
    )


def _framework_coverage_rows(cases: list[CaseRow]) -> list[FrameworkCoverageRow]:
    totals = total_controls_by_framework()
    names = framework_display_names()
    rows = framework_coverage(cases, totals)
    return [
        FrameworkCoverageRow(
            framework_key=row["framework_key"],
            framework_name=names.get(row["framework_key"], row["framework_key"]),
            total_controls=row["total_controls"],
            covered_controls=row["covered_controls"],
            coverage_pct=row["coverage_pct"],
        )
        for row in rows
    ]


def gather_report_metrics(
    db: Session, account_id: UUID, period_start: datetime, period_end: datetime
) -> ReportMetrics:
    cases_orm = _cases_in_period(db, account_id, period_start, period_end)
    cases = [_to_case_row(c) for c in cases_orm]
    counts = verdict_counts(cases)

    exposure = exposure_avoided(cases, risk_assumptions)
    incidents = _incidents_in_period(db, account_id, period_start, period_end)

    return ReportMetrics(
        period_start=period_start,
        period_end=period_end,
        emails_analyzed=len(cases),
        verdict_breakdown=VerdictBreakdown(**counts),
        threats_detected=counts["malicious"] + counts["suspicious"],
        threats_contained=_threats_contained(db, account_id, period_start, period_end),
        exposure_avoided_usd=exposure["total_usd"],
        exposure_by_attack_type=[
            ExposureByAttackType(
                attack_type=entry["attack_type"],
                count=entry["count"],
                avg_loss_usd=entry["avg_loss_usd"],
                subtotal_usd=entry["subtotal_usd"],
            )
            for entry in exposure["by_attack_type"]
        ],
        incidents_detected=len(incidents),
        early_warning_alerts_raised=_early_warning_alerts_raised(db, account_id, period_start, period_end),
        human_risk=_human_risk_summary(db, account_id, period_start, period_end),
        framework_coverage=_framework_coverage_rows(cases),
    )
