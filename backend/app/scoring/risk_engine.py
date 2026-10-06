"""Fuses indicator findings into a single 0-100 risk score and verdict band."""

from __future__ import annotations

from app.models.schemas import Indicator, Verdict

SAFE_MAX = 24
SUSPICIOUS_MAX = 54

# M3: the optional ML classifier signal (app.ml.classifier) nudges the rule-based score by at
# most this many points, in either direction. Bounded deliberately so the guardrail "ML alone
# never turns a benign case malicious" is true by construction, not just empirically observed:
# a case the rule engine already scores near 0 can reach at most ML_MAX_CONTRIBUTION_POINTS even
# at ml_probability=1.0 — well under SAFE_MAX, let alone SUSPICIOUS_MAX. The ML signal nudges the
# score; it never redefines what these verdict bands mean.
ML_MAX_CONTRIBUTION_POINTS = 15

# Detection enhancement: the optional LLM intent signal (app.reasoning.llm_analyst) — the
# model's own independent read of the email's apparent intent, returned from the same call
# that produces the human analyst narrative. Deliberately a DIFFERENT shape of bound from
# ML_MAX_CONTRIBUTION_POINTS above: the ML signal is a nudge that can move the score in
# EITHER direction around a neutral midpoint, but the LLM intent signal is additive-only — it
# can only ever ADD points (see compute_score below), never subtract. That one property is
# what makes "a prompt-injection attempt telling the model to mark this email safe cannot
# lower the score" true by construction rather than by hoping the model resists the attempt:
# the worst case a successfully-injected or simply wrong "intent_risk=0" response produces is
# zero contribution, exactly as if the LLM had never been called. It can never undo what the
# deterministic indicators (and ML, if enabled) already computed, and the deterministic rules
# are never bypassed or recomputed by it — they run first and are the only input the cap is
# measured against.
#
# The cap itself is set well under SAFE_MAX (24), not just under 100, so the structural
# guarantee is specific: a case with ZERO deterministic indicators triggered can reach at most
# LLM_INTENT_MAX_CONTRIBUTION_POINTS from the LLM signal alone, which stays inside the SAFE
# band regardless of how confidently (or how adversarially) the model scores intent. See
# tests/unit/test_risk_engine.py for the tests that prove this structurally rather than just
# asserting it in a comment, and app.reasoning.llm_analyst for the strict schema validation
# that rejects (rather than clamps-and-trusts) any out-of-range or malformed model output
# before it ever reaches this module.
LLM_INTENT_MAX_CONTRIBUTION_POINTS = 20


def compute_score(
    indicators: list[Indicator],
    ml_probability: float | None = None,
    llm_intent_risk: float | None = None,
) -> int:
    total = sum(indicator.score for indicator in indicators)
    if ml_probability is not None:
        total += (ml_probability - 0.5) * 2 * ML_MAX_CONTRIBUTION_POINTS
    if llm_intent_risk is not None:
        # Clamped here too, even though app.reasoning.llm_analyst's Pydantic schema already
        # rejects an out-of-range value before it ever reaches this function — defense in
        # depth, and the actual enforcement point for "additive-only": max(0.0, ...) means a
        # negative value (however it got here) can never lower `total`, and min(CAP, ...)
        # means no single call can ever contribute more than the documented cap.
        total += max(0.0, min(LLM_INTENT_MAX_CONTRIBUTION_POINTS, llm_intent_risk))
    return max(0, min(100, round(total)))


def verdict_for_score(score: int) -> Verdict:
    if score <= SAFE_MAX:
        return Verdict.SAFE
    if score <= SUSPICIOUS_MAX:
        return Verdict.SUSPICIOUS
    return Verdict.MALICIOUS


def fuse(
    indicators: list[Indicator],
    ml_probability: float | None = None,
    llm_intent_risk: float | None = None,
) -> tuple[int, Verdict]:
    score = compute_score(indicators, ml_probability, llm_intent_risk)
    return score, verdict_for_score(score)
