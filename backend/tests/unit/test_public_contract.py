"""app.analysis.public_contract: the stable /v1/analyze/email shape. Pure reshaping only."""

from __future__ import annotations

from app.analysis.public_contract import build_public_result, framework_tags, public_auth, summary_sentence
from app.models.schemas import AuthResults, AuthResultValue, FrameworkControlRef, Indicator, Severity, Verdict


def _ind(id_: str, title: str, score: float, category: str = "link") -> Indicator:
    return Indicator(id=id_, category=category, title=title, description="d", severity=Severity.HIGH, score=score)


def _ref(ind: str, control: str) -> FrameworkControlRef:
    return FrameworkControlRef(indicator_id=ind, control_id=control, control_name="x")


def test_exact_keys_and_safe_is_published_as_clean():
    out = build_public_result(
        verdict=Verdict.SAFE, score=8, indicators=[], framework_mappings={},
        auth_results=AuthResults(), llm_intent_category=None,
    )
    assert set(out) == {"verdict", "score", "category", "summary", "top_indicators", "auth", "frameworks"}
    assert out["verdict"] == "clean"
    assert out["category"] == "none"
    assert out["top_indicators"] == []
    assert out["summary"] == "Clean (8/100): Cordon found no phishing indicators in this email."


def test_top_indicators_are_the_three_highest_scoring_titles():
    inds = [_ind("a", "A", 10), _ind("b", "B", 40, "sender"), _ind("c", "C", 30), _ind("d", "D", 20)]
    out = build_public_result(
        verdict=Verdict.MALICIOUS, score=90, indicators=inds, framework_mappings={},
        auth_results=AuthResults(), llm_intent_category=None,
    )
    assert out["top_indicators"] == ["B", "C", "D"]
    assert out["category"] == "sender"  # top indicator's category without an LLM assessment
    assert out["summary"] == "Malicious (90/100): 4 findings, the strongest being: B."


def test_llm_intent_category_wins_when_present():
    out = build_public_result(
        verdict=Verdict.SUSPICIOUS, score=50, indicators=[_ind("a", "A", 10)], framework_mappings={},
        auth_results=AuthResults(), llm_intent_category="credential_phishing",
    )
    assert out["category"] == "credential_phishing"


def test_low_score_with_findings_says_not_enough_to_flag():
    assert summary_sentence(Verdict.SAFE, 12, [_ind("a", "URL shortener used", 12)]) == (
        "Clean (12/100): 1 finding, not enough to flag this email (strongest: URL shortener used)."
    )


def test_auth_collapses_to_pass_fail_none():
    auth = AuthResults(spf=AuthResultValue.SOFTFAIL, dkim=AuthResultValue.PASS, dmarc=AuthResultValue.TEMPERROR)
    assert public_auth(auth) == {"spf": "fail", "dkim": "pass", "dmarc": "none"}
    assert public_auth(AuthResults()) == {"spf": "none", "dkim": "none", "dmarc": "none"}
    assert public_auth(AuthResults(spf=AuthResultValue.PERMERROR)).get("spf") == "fail"


def test_framework_tags_are_ordered_labeled_and_deduplicated():
    mappings = {
        "soc2": [_ref("a", "CC7.2")],
        "iso_27001": [_ref("a", "A.5.7")],
        "mitre_attack": [_ref("a", "T1566"), _ref("b", "T1566"), _ref("b", "T1566.002")],
        "nist_csf": [_ref("a", "DE.CM-01")],
    }
    assert framework_tags(mappings) == ["MITRE T1566", "MITRE T1566.002", "NIST DE.CM-01", "ISO A.5.7", "SOC 2 CC7.2"]
