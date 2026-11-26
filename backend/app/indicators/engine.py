"""Runs the full set of deterministic indicator rules over a parsed email."""

from __future__ import annotations

from app.indicators import (
    account_lists,
    account_takeover,
    ai_authored,
    attachment_risk,
    auth_failures,
    chat_context,
    combinations,
    credential_payment,
    domain_age_heuristic,
    hidden_instruction_payload,
    institutional_sender_mismatch,
    known_bad_sender,
    known_bad_urls,
    link_analysis,
    lookalike_domain,
    lure_theme,
    sender_history,
    sender_mismatch,
    trusted_sender_anomaly,
    urgency_language,
)
from app.indicators.base import IndicatorRule
from app.models.schemas import Indicator
from app.channels.message import Message
from app.sender_history.aggregation import SenderHistorySnapshot, empty_sender_history

_RULES: list[IndicatorRule] = [
    sender_mismatch.evaluate,
    lookalike_domain.evaluate,
    urgency_language.evaluate,
    credential_payment.evaluate,
    link_analysis.evaluate,
    attachment_risk.evaluate,
    auth_failures.evaluate,
    ai_authored.evaluate,
    chat_context.evaluate,
    sender_history.evaluate,
    trusted_sender_anomaly.evaluate,
    account_takeover.evaluate,
    known_bad_urls.evaluate,
    known_bad_sender.evaluate,
    domain_age_heuristic.evaluate,
    hidden_instruction_payload.evaluate,
    account_lists.evaluate,
    lure_theme.evaluate,
    institutional_sender_mismatch.evaluate,
]


def run_indicators(
    email: Message, sender_history: SenderHistorySnapshot | None = None
) -> list[Indicator]:
    history = sender_history if sender_history is not None else empty_sender_history()
    indicators: list[Indicator] = []
    for rule in _RULES:
        indicators.extend(rule(email, history))
    indicators.extend(combinations.evaluate(indicators))
    return merge_duplicates(indicators)


def merge_duplicates(indicators: list[Indicator]) -> list[Indicator]:
    """One finding per indicator id (ids are the UI's list keys). Evidence is unioned in order.
    A repeat that adds no new evidence (the same value reported twice) adds no points; an
    entry about a distinct value (e.g. a second look-alike domain) keeps adding its score, as
    it did when it was a separate finding."""
    merged: dict[str, Indicator] = {}
    for ind in indicators:
        prior = merged.get(ind.id)
        if prior is None:
            merged[ind.id] = ind
            continue
        new_evidence = [e for e in ind.evidence if e not in prior.evidence]
        if not new_evidence:
            continue
        top = ind if ind.score > prior.score else prior
        merged[ind.id] = top.model_copy(
            update={"evidence": [*prior.evidence, *new_evidence], "score": prior.score + ind.score}
        )
    return list(merged.values())
