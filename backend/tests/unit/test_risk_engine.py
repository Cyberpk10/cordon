from __future__ import annotations

import pytest

from app.models.schemas import Indicator, Severity, Verdict
from app.scoring.risk_engine import (
    LLM_INTENT_MAX_CONTRIBUTION_POINTS,
    ML_MAX_CONTRIBUTION_POINTS,
    SAFE_MAX,
    SUSPICIOUS_MAX,
    compute_score,
    fuse,
    verdict_for_score,
)


def _indicator(score: float) -> Indicator:
    return Indicator(
        id="TEST",
        category="test",
        title="test",
        description="test",
        evidence=[],
        severity=Severity.LOW,
        score=score,
    )


def test_no_indicators_scores_zero():
    assert compute_score([]) == 0


def test_score_sums_indicator_scores():
    assert compute_score([_indicator(10), _indicator(20)]) == 30


def test_score_caps_at_100():
    assert compute_score([_indicator(80), _indicator(80)]) == 100


@pytest.mark.parametrize(
    "score,expected",
    [
        (0, Verdict.SAFE),
        (24, Verdict.SAFE),
        (25, Verdict.SUSPICIOUS),
        (54, Verdict.SUSPICIOUS),
        (55, Verdict.MALICIOUS),
        (100, Verdict.MALICIOUS),
    ],
)
def test_verdict_bands(score, expected):
    assert verdict_for_score(score) == expected


def test_fuse_returns_score_and_verdict():
    score, verdict = fuse([_indicator(60)])
    assert score == 60
    assert verdict == Verdict.MALICIOUS


def test_ml_probability_none_is_a_no_op():
    """The default (no ML signal) path must be byte-identical to the pre-M3 behavior."""
    assert compute_score([_indicator(10)], ml_probability=None) == compute_score([_indicator(10)])


def test_ml_probability_at_one_adds_max_contribution():
    score = compute_score([_indicator(10)], ml_probability=1.0)
    assert score == 10 + ML_MAX_CONTRIBUTION_POINTS


def test_ml_probability_at_zero_subtracts_max_contribution():
    score = compute_score([_indicator(10)], ml_probability=0.0)
    assert score == max(0, 10 - ML_MAX_CONTRIBUTION_POINTS)


def test_ml_probability_at_half_is_a_no_op():
    """0.5 (maximally uncertain) contributes nothing — the blend is centered, not biased."""
    assert compute_score([_indicator(10)], ml_probability=0.5) == 10


@pytest.mark.parametrize("ml_probability", [0.0, 0.25, 0.5, 0.75, 1.0])
def test_ml_signal_alone_can_never_reach_malicious_from_a_clean_rule_score(ml_probability):
    """The guardrail, expressed structurally: with zero rule-based indicators, no ML
    probability (however confident) can push the score past SAFE_MAX, let alone into
    MALICIOUS — because ML_MAX_CONTRIBUTION_POINTS < SAFE_MAX by construction."""
    score, verdict = fuse([], ml_probability=ml_probability)
    assert score <= SAFE_MAX
    assert verdict == Verdict.SAFE


# --- LLM intent signal: bounded, additive-only (app.reasoning.llm_analyst) -------------


def test_llm_intent_risk_none_is_a_no_op():
    """The default (no LLM signal) path must be byte-identical to the pre-this-feature
    behavior — exact mirror of test_ml_probability_none_is_a_no_op above."""
    assert compute_score([_indicator(10)], llm_intent_risk=None) == compute_score([_indicator(10)])


def test_llm_intent_risk_at_cap_adds_exactly_the_cap():
    score = compute_score([_indicator(10)], llm_intent_risk=LLM_INTENT_MAX_CONTRIBUTION_POINTS)
    assert score == 10 + LLM_INTENT_MAX_CONTRIBUTION_POINTS


def test_llm_intent_risk_zero_is_a_no_op():
    assert compute_score([_indicator(10)], llm_intent_risk=0) == 10


@pytest.mark.parametrize("llm_intent_risk", [1, 5, 10, LLM_INTENT_MAX_CONTRIBUTION_POINTS])
def test_llm_intent_risk_is_purely_additive(llm_intent_risk):
    """Unlike ml_probability (which can raise OR lower the score around a neutral midpoint),
    every valid llm_intent_risk value can only ever raise it."""
    assert compute_score([_indicator(10)], llm_intent_risk=llm_intent_risk) == 10 + llm_intent_risk


def test_llm_intent_risk_above_the_cap_is_clamped_not_honored():
    """Defense in depth: app.reasoning.llm_analyst's schema validation should already reject
    an out-of-range value before it ever reaches compute_score, but this function does not
    trust that alone — an impossibly large value is clamped to the documented cap, never
    added in full."""
    score = compute_score([_indicator(10)], llm_intent_risk=LLM_INTENT_MAX_CONTRIBUTION_POINTS + 500)
    assert score == 10 + LLM_INTENT_MAX_CONTRIBUTION_POINTS


def test_llm_intent_risk_cannot_be_negative():
    """The property that makes "additive-only" a real guarantee rather than a convention: a
    negative llm_intent_risk (however it got here) is floored at zero, never subtracted from
    the score the deterministic indicators already computed. This is the one scenario — a
    successful prompt-injection attempt telling the model to report a negative or zero risk —
    that an additive-only design exists specifically to neutralize."""
    assert compute_score([_indicator(10)], llm_intent_risk=-50) == 10


def test_llm_intent_risk_cannot_lower_a_malicious_score():
    """Even at its most generous reading (a successfully-injected "mark this safe" response
    reporting intent_risk=0), the LLM signal cannot undo what the deterministic rules already
    established — a case that's MALICIOUS on indicators alone stays exactly as malicious."""
    score, verdict = fuse([_indicator(80)], llm_intent_risk=0)
    assert score == 80
    assert verdict == Verdict.MALICIOUS


@pytest.mark.parametrize(
    "llm_intent_risk", [0, 1, 5, 10, LLM_INTENT_MAX_CONTRIBUTION_POINTS, 999]
)
def test_llm_intent_signal_alone_can_never_leave_the_safe_band_from_a_clean_rule_score(
    llm_intent_risk,
):
    """The structural guarantee this feature's cap exists to provide: with zero rule-based
    indicators, no intent_risk value the LLM could report (even an out-of-range one, which
    gets clamped) can push the score past SAFE_MAX — because
    LLM_INTENT_MAX_CONTRIBUTION_POINTS < SAFE_MAX by construction, exactly mirroring the ML
    guardrail above. 'The deterministic rules remain authoritative' is true by construction,
    not convention."""
    score, verdict = fuse([], llm_intent_risk=llm_intent_risk)
    assert score <= SAFE_MAX
    assert verdict == Verdict.SAFE


def test_ml_and_llm_signals_combined_cannot_manufacture_malicious_from_a_clean_rule_score():
    """Both enrichment signals maxed out at once, with zero rule-based indicators: their
    combined ceiling (ML_MAX_CONTRIBUTION_POINTS + LLM_INTENT_MAX_CONTRIBUTION_POINTS = 35)
    stays comfortably under SUSPICIOUS_MAX (54), so stacking both bounded signals can nudge a
    clean case into SUSPICIOUS at most — never MALICIOUS. Multiple independently-bounded
    enrichment signals are not a loophole around any single signal's own cap."""
    score, verdict = fuse(
        [], ml_probability=1.0, llm_intent_risk=LLM_INTENT_MAX_CONTRIBUTION_POINTS
    )
    assert ML_MAX_CONTRIBUTION_POINTS + LLM_INTENT_MAX_CONTRIBUTION_POINTS < SUSPICIOUS_MAX
    assert score == ML_MAX_CONTRIBUTION_POINTS + LLM_INTENT_MAX_CONTRIBUTION_POINTS
    assert verdict != Verdict.MALICIOUS


def test_llm_intent_risk_can_raise_a_borderline_case_into_suspicious():
    """The positive case, not just the guardrails: this signal is meant to matter. A rule
    score just inside SAFE, plus a meaningful intent_risk, can legitimately cross into
    SUSPICIOUS — "bounded, additive influence" means it genuinely influences, within its cap,
    not that it's inert."""
    rule_only_score, rule_only_verdict = fuse([_indicator(SAFE_MAX)])
    assert rule_only_verdict == Verdict.SAFE

    score, verdict = fuse([_indicator(SAFE_MAX)], llm_intent_risk=LLM_INTENT_MAX_CONTRIBUTION_POINTS)
    assert score > rule_only_score
    assert verdict == Verdict.SUSPICIOUS
