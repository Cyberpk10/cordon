from __future__ import annotations

import pytest

from app.analysis import email_pipeline as email_pipeline_module
from app.api.routes import analyze as analyze_module
from app.indicators.engine import run_indicators
from app.parsing.eml_parser import parse_eml
from app.reasoning.llm_analyst import LLMAssessment
from app.scoring.risk_engine import compute_score
from tests.conftest import FIXTURES_DIR


def _all_labeled_filenames(labeled_samples: dict[str, str]) -> list[str]:
    return sorted(labeled_samples.keys())


def test_health_check(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_rejects_non_eml_file(authed_client):
    response = authed_client.post(
        "/api/analyze", files={"file": ("note.txt", b"hello", "text/plain")}
    )
    assert response.status_code == 400


def test_rejects_empty_file(authed_client):
    response = authed_client.post("/api/analyze", files={"file": ("empty.eml", b"", "message/rfc822")})
    assert response.status_code == 400


@pytest.mark.parametrize(
    "filename",
    [
        "phishing_lookalike_paypal.eml",
        "phishing_bec_wire_transfer.eml",
        "phishing_shortener_credential_harvest.eml",
        "benign_newsletter.eml",
        "benign_internal_it_notice.eml",
        "benign_legit_password_reset.eml",
    ],
)
def test_labeled_samples_match_expected_verdict(authed_client, load_eml, labeled_samples, filename):
    expected_verdict = labeled_samples[filename]
    raw = load_eml(filename)

    response = authed_client.post(
        "/api/analyze", files={"file": (filename, raw, "message/rfc822")}
    )

    assert response.status_code == 200
    body = response.json()
    assert body["verdict"] == expected_verdict, (
        f"{filename}: expected {expected_verdict}, got {body['verdict']} "
        f"(score={body['score']}, indicators={[i['id'] for i in body['indicators']]})"
    )


def test_malicious_sample_has_populated_framework_mappings(authed_client, load_eml):
    raw = load_eml("phishing_lookalike_paypal.eml")
    response = authed_client.post(
        "/api/analyze", files={"file": ("phishing_lookalike_paypal.eml", raw, "message/rfc822")}
    )
    body = response.json()
    mappings = body["framework_mappings"]
    for framework_key in ("mitre_attack", "nist_csf", "iso_27001", "soc2"):
        assert len(mappings[framework_key]) > 0


def test_safe_sample_has_no_indicators(authed_client, load_eml):
    raw = load_eml("benign_newsletter.eml")
    response = authed_client.post(
        "/api/analyze", files={"file": ("benign_newsletter.eml", raw, "message/rfc822")}
    )
    body = response.json()
    # A brand-new account has no sender history yet, so its very first analysis of any
    # sender legitimately raises FIRST_CONTACT_SENDER (M8 Stage 3a) — low-weight by design,
    # verdict stays safe either way.
    ids = {i["id"] for i in body["indicators"]}
    assert ids == {"FIRST_CONTACT_SENDER"}
    assert body["score"] == 8
    assert body["verdict"] == "safe"


def test_response_summary_reflects_auth_results(authed_client, load_eml):
    raw = load_eml("phishing_bec_wire_transfer.eml")
    response = authed_client.post(
        "/api/analyze", files={"file": ("phishing_bec_wire_transfer.eml", raw, "message/rfc822")}
    )
    body = response.json()
    assert body["summary"]["auth_results"]["spf"] == "fail"
    assert body["summary"]["from_address"] == "ceo@acmecorp-executives.com"


def test_llm_reasoning_disabled_by_default_omits_narrative(authed_client, load_eml):
    raw = load_eml("phishing_lookalike_paypal.eml")
    response = authed_client.post(
        "/api/analyze", files={"file": ("phishing_lookalike_paypal.eml", raw, "message/rfc822")}
    )
    body = response.json()
    assert body["analyst_narrative"] is None
    assert body["analyst_model"] is None


def test_llm_reasoning_enabled_populates_narrative(authed_client, load_eml, monkeypatch):
    monkeypatch.setattr(analyze_module.settings, "enable_llm_reasoning", True)

    def fake_assessment(parsed_email, indicators, score, verdict):
        return LLMAssessment(
            narrative="Mocked analyst narrative describing the phishing risk.",
            model="claude-haiku-4-5",
            intent_category="credential_phishing",
            intent_risk=5,
            confidence="high",
            brief_reasons=["lookalike domain", "urgency language"],
        )

    monkeypatch.setattr(email_pipeline_module, "generate_llm_assessment", fake_assessment)

    raw = load_eml("phishing_lookalike_paypal.eml")
    response = authed_client.post(
        "/api/analyze", files={"file": ("phishing_lookalike_paypal.eml", raw, "message/rfc822")}
    )

    assert response.status_code == 200
    body = response.json()
    assert body["analyst_narrative"] == "Mocked analyst narrative describing the phishing risk."
    assert body["analyst_model"] == "claude-haiku-4-5"
    assert body["llm_intent_category"] == "credential_phishing"
    assert body["llm_intent_risk"] == 5
    assert body["llm_intent_confidence"] == "high"
    assert body["llm_intent_reasons"] == ["lookalike domain", "urgency language"]
    # The rule-based result already maxes this fixture at 100 — the LLM signal is additive,
    # so it can only hold the ceiling, never actually move it in this particular case.
    # test_risk_engine.py and test_llm_analyst.py prove the general bounded/additive
    # behavior on scores that aren't already pinned at the cap.
    assert body["verdict"] == "malicious"
    assert body["score"] == 100


def test_llm_intent_risk_raises_a_borderline_score_within_its_cap(
    authed_client, load_eml, monkeypatch
):
    """Unlike the test above (a fixture that's already rule-score-100, where the additive
    signal has no visible room to move), this uses a fixture with headroom below 100 and
    confirms the LLM's intent_risk genuinely gets added on top of the deterministic score,
    not just carried along for display.

    The rule-only baseline is computed directly through the indicator engine (sender_history=
    None, matching a brand-new account) rather than via a prior live POST — a real live call
    would persist a Case and change this sender's FIRST_CONTACT_SENDER classification for any
    *second* call on the same account, which would make the two calls' rule-only components
    genuinely different and silently break this comparison. One live call is enough to
    exercise the real pipeline end to end; the baseline is deterministic.
    """
    raw = load_eml("benign_newsletter.eml")
    baseline_indicators = run_indicators(parse_eml(raw), sender_history=None)
    baseline = compute_score(baseline_indicators)

    monkeypatch.setattr(analyze_module.settings, "enable_llm_reasoning", True)

    def fake_assessment(parsed_email, indicators, score, verdict):
        return LLMAssessment(
            narrative="Elevated risk based on independent intent read.",
            model="claude-haiku-4-5",
            intent_category="other_suspicious",
            intent_risk=20,
            confidence="medium",
            brief_reasons=["tone mismatch"],
        )

    monkeypatch.setattr(email_pipeline_module, "generate_llm_assessment", fake_assessment)

    response = authed_client.post(
        "/api/analyze", files={"file": ("benign_newsletter.eml", raw, "message/rfc822")}
    )
    body = response.json()
    assert body["score"] == min(100, baseline + 20)
    assert body["llm_intent_risk"] == 20


def test_llm_reasoning_enabled_without_api_key_returns_null_narrative(authed_client, load_eml, monkeypatch):
    monkeypatch.setattr(analyze_module.settings, "enable_llm_reasoning", True)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    raw = load_eml("benign_newsletter.eml")
    response = authed_client.post(
        "/api/analyze", files={"file": ("benign_newsletter.eml", raw, "message/rfc822")}
    )

    assert response.status_code == 200
    body = response.json()
    assert body["analyst_narrative"] is None
    assert body["analyst_model"] is None
    assert body["llm_intent_category"] is None
    assert body["llm_intent_risk"] is None
    assert body["llm_intent_confidence"] is None
    assert body["llm_intent_reasons"] is None
    assert body["verdict"] == "safe"


def test_analyze_persists_a_retrievable_case(authed_client, load_eml):
    raw = load_eml("phishing_lookalike_paypal.eml")
    analyze_response = authed_client.post(
        "/api/analyze", files={"file": ("phishing_lookalike_paypal.eml", raw, "message/rfc822")}
    )
    assert analyze_response.status_code == 200
    analyze_body = analyze_response.json()
    assert analyze_body["id"]
    assert analyze_body["created_at"]

    case_response = authed_client.get(f"/api/cases/{analyze_body['id']}")
    assert case_response.status_code == 200
    case_body = case_response.json()

    assert case_body["id"] == analyze_body["id"]
    assert case_body["verdict"] == analyze_body["verdict"]
    assert case_body["score"] == analyze_body["score"]
    assert case_body["indicators"] == analyze_body["indicators"]
    assert case_body["framework_mappings"] == analyze_body["framework_mappings"]
    assert case_body["filename"] == "phishing_lookalike_paypal.eml"
    assert case_body["from_addr"] == analyze_body["summary"]["from_address"]
    assert case_body["subject"] == analyze_body["summary"]["subject"]
    assert case_body["llm_intent_category"] == analyze_body["llm_intent_category"]
    assert case_body["llm_intent_risk"] == analyze_body["llm_intent_risk"]
    assert case_body["llm_intent_confidence"] == analyze_body["llm_intent_confidence"]
    assert case_body["llm_intent_reasons"] == analyze_body["llm_intent_reasons"]
