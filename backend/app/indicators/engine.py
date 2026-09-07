"""Runs the full set of deterministic indicator rules over a parsed email."""

from __future__ import annotations

from app.indicators import (
    ai_authored,
    attachment_risk,
    auth_failures,
    chat_context,
    credential_payment,
    domain_age_heuristic,
    known_bad_urls,
    link_analysis,
    lookalike_domain,
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
    known_bad_urls.evaluate,
    domain_age_heuristic.evaluate,
]


def run_indicators(
    email: Message, sender_history: SenderHistorySnapshot | None = None
) -> list[Indicator]:
    history = sender_history if sender_history is not None else empty_sender_history()
    indicators: list[Indicator] = []
    for rule in _RULES:
        indicators.extend(rule(email, history))
    return indicators
