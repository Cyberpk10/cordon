"""Shared raw-bytes -> parsed -> indicators -> score -> framework-mappings pipeline (M8
Stage 3). Extracted out of app.api.routes.analyze so the new inbound-email webhook
(app.api.routes.inbound) doesn't need a third copy of this sequence. app.api.routes.messages
has its own independent, smaller pipeline (no eml parsing/raw storage/LLM narrative involved
there) — left as-is, out of scope.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.core.config import settings
from app.indicators.engine import run_indicators
from app.ml.classifier import predict as ml_predict
from app.mapping.framework_mapper import map_indicators
from app.models.schemas import FrameworkControlRef, Indicator, Verdict
from app.parsing.eml_parser import ParsedEmail, parse_eml
from app.reasoning.llm_analyst import generate_llm_assessment
from app.scoring.risk_engine import fuse
from app.sender_history.aggregation import SenderHistorySnapshot


@dataclass(frozen=True)
class PipelineResult:
    parsed: ParsedEmail
    indicators: list[Indicator]
    score: int
    verdict: Verdict
    framework_mappings: dict[str, list[FrameworkControlRef]]
    analyst_narrative: str | None
    analyst_model: str | None
    # Bounded, additive-only LLM intent signal (app.reasoning.llm_analyst,
    # app.scoring.risk_engine.LLM_INTENT_MAX_CONTRIBUTION_POINTS) — None across all four
    # fields together whenever no LLM assessment was obtained (disabled, no API key, call
    # failure, or output that failed strict schema validation), exactly mirroring how
    # analyst_narrative/analyst_model already behave.
    llm_intent_category: str | None
    llm_intent_risk: int | None
    llm_intent_confidence: str | None
    llm_intent_reasons: list[str] | None
    ml_probability: float | None
    ml_model_version: str | None


def run_email_pipeline(
    raw_bytes: bytes, sender_history: SenderHistorySnapshot | None = None
) -> PipelineResult:
    """Parses raw .eml bytes and runs the full rule-based + optional ML + optional LLM analysis.
    Raises whatever parse_eml raises on malformed input — callers translate that into their own
    error response (a 400 for a direct upload, a quiet reject for a webhook). `sender_history`
    is the caller's pre-loaded per-account correspondence history (M8 Stage 3a,
    app.sender_history.aggregation) — None for callers with no account context."""
    parsed = parse_eml(raw_bytes)

    indicators = run_indicators(parsed, sender_history)

    ml_probability: float | None = None
    ml_model_version: str | None = None
    if settings.enable_ml_classifier:
        ml_probability, ml_model_version = ml_predict(parsed, indicators)

    # Pass 1: the deterministic rules + ML result. This is what the LLM (if enabled) is shown
    # as already-final context to react to, AND what the pipeline falls back to byte-for-byte
    # whenever the LLM is off, has no key, times out, or returns anything that fails strict
    # schema validation — "the deterministic rules remain authoritative" holds because this
    # value, not the LLM's opinion of it, is the baseline Pass 2 below can only ever add to.
    rule_score, rule_verdict = fuse(indicators, ml_probability)

    llm_assessment = None
    if settings.enable_llm_reasoning:
        llm_assessment = generate_llm_assessment(parsed, indicators, rule_score, rule_verdict)

    # Pass 2: fold in the bounded, additive-only LLM intent signal. llm_intent_risk is None
    # (a no-op — see risk_engine.compute_score) whenever llm_assessment is None, so this is
    # exactly Pass 1's score/verdict, unchanged, whenever the LLM wasn't available or usable.
    llm_intent_risk = llm_assessment.intent_risk if llm_assessment else None
    score, verdict = fuse(indicators, ml_probability, llm_intent_risk)

    framework_mappings = map_indicators([i.id for i in indicators])

    return PipelineResult(
        parsed=parsed,
        indicators=indicators,
        score=score,
        verdict=verdict,
        framework_mappings=framework_mappings,
        analyst_narrative=llm_assessment.narrative if llm_assessment else None,
        analyst_model=llm_assessment.model if llm_assessment else None,
        llm_intent_category=llm_assessment.intent_category if llm_assessment else None,
        llm_intent_risk=llm_assessment.intent_risk if llm_assessment else None,
        llm_intent_confidence=llm_assessment.confidence if llm_assessment else None,
        llm_intent_reasons=llm_assessment.brief_reasons if llm_assessment else None,
        ml_probability=ml_probability,
        ml_model_version=ml_model_version,
    )
