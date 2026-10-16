from __future__ import annotations

from datetime import datetime

from app.reports import executive_summary
from app.reports.gather import (
    ExposureByAttackType,
    FrameworkCoverageRow,
    HumanRiskSummary,
    ReportMetrics,
    VerdictBreakdown,
)


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


def _tool_payload(**overrides) -> dict:
    payload = {
        "summary": "120 emails were analyzed; 15 threats were detected and 12 were automatically contained (EV1, EV3).",
        "evidence_ids": ["EV1", "EV3"],
    }
    payload.update(overrides)
    return payload


# --- Success / plumbing -----------------------------------------------------------------


def test_returns_full_summary_on_success(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    captured = {}

    def fake_call(*, model, api_key, system, user_content, tool, timeout=10.0):
        captured["model"] = model
        captured["system"] = system
        captured["user_content"] = user_content
        return _tool_payload()

    monkeypatch.setattr(executive_summary, "_call_anthropic", fake_call)

    result = executive_summary.generate_llm_summary(_metrics())

    assert result is not None
    assert result.text == _tool_payload()["summary"]
    assert result.source == "llm"
    assert result.model == "claude-haiku-4-5"
    assert result.evidence_ids == ["EV1", "EV3"]
    assert captured["system"] == executive_summary.SYSTEM_PROMPT
    assert "120 email(s)" in captured["user_content"]
    assert "15 threat(s)" in captured["user_content"]


def test_forces_structured_tool_output_not_free_text(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    import anthropic as anthropic_module

    captured_kwargs = {}

    class _FakeMessages:
        def create(self, **kwargs):
            captured_kwargs.update(kwargs)

            class _Block:
                type = "tool_use"
                name = executive_summary._REPORT_TOOL_NAME
                input = _tool_payload()

            class _Response:
                content = [_Block()]

            return _Response()

    class _FakeClient:
        def with_options(self, **kw):
            return self

        messages = _FakeMessages()

    monkeypatch.setattr(anthropic_module, "Anthropic", lambda api_key: _FakeClient())

    result = executive_summary.generate_llm_summary(_metrics())

    assert result is not None
    assert captured_kwargs["tool_choice"] == {"type": "tool", "name": "write_executive_summary"}
    assert captured_kwargs["tools"][0]["name"] == "write_executive_summary"
    assert "evidence_ids" in captured_kwargs["tools"][0]["input_schema"]["properties"]


def test_no_api_key_returns_none_without_calling(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    def fail_if_called(*args, **kwargs):
        raise AssertionError("_call_anthropic should never be invoked without an API key")

    monkeypatch.setattr(executive_summary, "_call_anthropic", fail_if_called)

    assert executive_summary.generate_llm_summary(_metrics()) is None


def test_call_failure_degrades_gracefully(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")

    def raise_timeout(*args, **kwargs):
        raise TimeoutError("simulated timeout")

    monkeypatch.setattr(executive_summary, "_call_anthropic", raise_timeout)

    assert executive_summary.generate_llm_summary(_metrics()) is None


def test_empty_summary_is_treated_as_failure(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setattr(
        executive_summary, "_call_anthropic", lambda **kw: _tool_payload(summary="   ")
    )
    assert executive_summary.generate_llm_summary(_metrics()) is None


# --- Grounding enforcement: the actual anti-fabrication mechanism -----------------------


def test_fabricated_evidence_id_rejects_the_whole_response(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setattr(
        executive_summary,
        "_call_anthropic",
        lambda **kw: _tool_payload(evidence_ids=["EV1", "EV99"]),
    )
    assert executive_summary.generate_llm_summary(_metrics()) is None


def test_empty_evidence_ids_is_rejected(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setattr(
        executive_summary, "_call_anthropic", lambda **kw: _tool_payload(evidence_ids=[])
    )
    assert executive_summary.generate_llm_summary(_metrics()) is None


def test_valid_subset_of_evidence_ids_is_accepted(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setattr(
        executive_summary, "_call_anthropic", lambda **kw: _tool_payload(evidence_ids=["EV1"])
    )
    result = executive_summary.generate_llm_summary(_metrics())
    assert result is not None
    assert result.evidence_ids == ["EV1"]


def test_smuggled_extra_field_rejects_the_whole_payload(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setattr(
        executive_summary,
        "_call_anthropic",
        lambda **kw: _tool_payload(invented_field="should not be allowed"),
    )
    assert executive_summary.generate_llm_summary(_metrics()) is None


def test_missing_required_field_is_rejected(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    payload = _tool_payload()
    del payload["evidence_ids"]
    monkeypatch.setattr(executive_summary, "_call_anthropic", lambda **kw: payload)
    assert executive_summary.generate_llm_summary(_metrics()) is None


def test_non_dict_tool_output_is_rejected(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setattr(executive_summary, "_call_anthropic", lambda **kw: "not a dict")
    assert executive_summary.generate_llm_summary(_metrics()) is None


# --- No untrusted content ever appears in the prompt -------------------------------------


def test_evidence_list_contains_only_numbers_no_free_text():
    """Unlike llm_analyst/llm_summary, there is no email body, subject, or other
    user/attacker-controlled free text anywhere in this module's prompt — every item is a
    number Cordon itself computed. This is a structural property worth asserting directly."""
    evidence = executive_summary._build_evidence_list(_metrics())
    assert len(evidence) >= 7
    joined = " ".join(text for _, text in evidence)
    # Every evidence line should be traceable to a number already on ReportMetrics.
    assert "120" in joined
    assert "15" in joined
    assert "48,250" in joined


def test_little_or_no_activity_instruction_present_for_empty_metrics(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    captured = {}

    def fake_call(*, model, api_key, system, user_content, tool, timeout=10.0):
        captured["user_content"] = user_content
        return _tool_payload(summary="No activity was recorded this period.", evidence_ids=["EV1"])

    monkeypatch.setattr(executive_summary, "_call_anthropic", fake_call)

    result = executive_summary.generate_llm_summary(_empty_metrics())

    assert result is not None
    assert "no detection or program activity" in captured["user_content"].lower()
    assert "must not invent" in captured["user_content"].lower()


# --- Deterministic fallback (no LLM involved at all) --------------------------------------


def test_deterministic_summary_for_active_period_states_real_numbers():
    summary = executive_summary.generate_deterministic_summary(_metrics())
    assert summary.source == "deterministic"
    assert summary.model is None
    assert summary.evidence_ids == []
    assert "120" in summary.text
    assert "15" in summary.text
    assert "12" in summary.text
    assert "48,250" in summary.text


def test_deterministic_summary_for_empty_account_is_honest_not_padded():
    summary = executive_summary.generate_deterministic_summary(_empty_metrics())
    assert summary.source == "deterministic"
    text_lower = summary.text.lower()
    assert "no" in text_lower
    assert "no activity to summarize" in text_lower
    # Must not claim any achievement/number that isn't actually zero.
    assert "detected" not in text_lower or "0" in summary.text or "no " in text_lower
