from __future__ import annotations

import json
from datetime import datetime

from app.reports.executive_summary import ExecutiveSummary
from app.reports.gather import (
    ExposureByAttackType,
    FrameworkCoverageRow,
    HumanRiskSummary,
    ReportMetrics,
    VerdictBreakdown,
)
from app.reports.report_builder import ReportContext, build_json_report, build_pdf_report


def _metrics(**overrides) -> ReportMetrics:
    defaults = dict(
        period_start=datetime(2026, 1, 1),
        period_end=datetime(2026, 1, 31),
        emails_analyzed=120,
        verdict_breakdown=VerdictBreakdown(malicious=5, suspicious=10, safe=105),
        threats_detected=15,
        threats_contained=12,
        exposure_avoided_usd=48250.0,
        exposure_by_attack_type=[
            ExposureByAttackType(
                attack_type="credential_phishing", count=5, avg_loss_usd=9650.0, subtotal_usd=48250.0
            )
        ],
        incidents_detected=2,
        early_warning_alerts_raised=1,
        human_risk=HumanRiskSummary(
            campaigns_run=1,
            employees_tested=20,
            employees_clicked=3,
            employees_reported=5,
            employees_flagged_for_training=3,
        ),
        framework_coverage=[
            FrameworkCoverageRow(
                framework_key="mitre_attack",
                framework_name="MITRE ATT&CK",
                total_controls=50,
                covered_controls=10,
                coverage_pct=20.0,
            )
        ],
    )
    defaults.update(overrides)
    return ReportMetrics(**defaults)


def _empty_metrics() -> ReportMetrics:
    return _metrics(
        emails_analyzed=0,
        verdict_breakdown=VerdictBreakdown(malicious=0, suspicious=0, safe=0),
        threats_detected=0,
        threats_contained=0,
        exposure_avoided_usd=0.0,
        exposure_by_attack_type=[],
        incidents_detected=0,
        early_warning_alerts_raised=0,
        human_risk=HumanRiskSummary(
            campaigns_run=0, employees_tested=0, employees_clicked=0, employees_reported=0, employees_flagged_for_training=0
        ),
        framework_coverage=[],
    )


def _ctx(metrics: ReportMetrics, *, summary_source: str = "deterministic") -> ReportContext:
    return ReportContext(
        account_name="Acme Corp",
        period_start=metrics.period_start,
        period_end=metrics.period_end,
        generated_at=datetime(2026, 2, 1, 12, 0, 0),
        metrics=metrics,
        executive_summary=ExecutiveSummary(
            text="A real summary built only from the metrics above.",
            source=summary_source,
            model="claude-haiku-4-5" if summary_source == "llm" else None,
            evidence_ids=["EV1"] if summary_source == "llm" else [],
        ),
    )


def test_pdf_report_is_a_valid_pdf_with_active_data():
    pdf_bytes = build_pdf_report(_ctx(_metrics()))
    assert pdf_bytes[:4] == b"%PDF"
    assert len(pdf_bytes) > 1000


def test_pdf_report_renders_for_an_empty_account_without_error():
    pdf_bytes = build_pdf_report(_ctx(_empty_metrics()))
    assert pdf_bytes[:4] == b"%PDF"


def test_pdf_report_renders_with_an_llm_sourced_summary():
    pdf_bytes = build_pdf_report(_ctx(_metrics(), summary_source="llm"))
    assert pdf_bytes[:4] == b"%PDF"


def test_json_report_contains_every_real_metric():
    ctx = _ctx(_metrics())
    payload = json.loads(build_json_report(ctx))["cordon_security_compliance_report"]

    assert payload["account_name"] == "Acme Corp"
    assert payload["emails_analyzed"] == 120
    assert payload["verdict_breakdown"] == {"malicious": 5, "suspicious": 10, "safe": 105}
    assert payload["threats_detected"] == 15
    assert payload["threats_contained"] == 12
    assert payload["exposure_avoided_usd"] == 48250.0
    assert payload["incidents_detected"] == 2
    assert payload["early_warning_alerts_raised"] == 1
    assert payload["human_risk"]["campaigns_run"] == 1
    assert payload["human_risk"]["employees_flagged_for_training"] == 3
    assert payload["framework_coverage"][0]["framework_key"] == "mitre_attack"
    assert payload["framework_coverage"][0]["coverage_pct"] == 20.0
    assert payload["has_any_activity"] is True
    assert payload["executive_summary"]["text"] == "A real summary built only from the metrics above."
    assert payload["executive_summary"]["source"] == "deterministic"


def test_json_report_for_empty_account_reflects_honest_zeros_not_omission():
    ctx = _ctx(_empty_metrics())
    payload = json.loads(build_json_report(ctx))["cordon_security_compliance_report"]

    assert payload["emails_analyzed"] == 0
    assert payload["threats_detected"] == 0
    assert payload["exposure_avoided_usd"] == 0.0
    assert payload["has_any_activity"] is False


def test_methodology_note_discloses_estimate_nature_of_exposure_figure():
    """The report must never present the exposure-avoided figure as an audited/guaranteed
    number — this is load-bearing for "no fabricated numbers" even though the figure itself
    is real, since presenting an estimate as a certainty would itself be misleading."""
    from app.reports.report_builder import METHODOLOGY_NOTE

    assert "estimate" in METHODOLOGY_NOTE.lower()
    assert "not a guarantee" in METHODOLOGY_NOTE.lower()


def test_logo_asset_exists_on_disk():
    from app.reports.report_builder import _LOGO_PATH

    assert _LOGO_PATH.exists()
    assert _LOGO_PATH.read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"
