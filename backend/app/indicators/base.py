"""Shared types for indicator rule modules."""

from __future__ import annotations

from typing import Callable

from app.models.schemas import Indicator, Severity
from app.channels.message import Message
from app.sender_history.aggregation import SenderHistorySnapshot

# Each rule module exposes a top-level `evaluate(email, sender_history) -> list[Indicator]`
# matching this shape (M8 Stage 3a). `sender_history` is the caller's pre-loaded per-account
# correspondence history (app.sender_history.aggregation) — every rule that doesn't reason
# about it (all rules that predate Stage 3a) simply ignores the parameter, exactly mirroring
# how app.detections' rules ignore `baseline` when unused.
IndicatorRule = Callable[[Message, "SenderHistorySnapshot | None"], list[Indicator]]


def make_indicator(
    *,
    id: str,
    category: str,
    title: str,
    description: str,
    evidence: list[str],
    severity: Severity,
    score: float,
) -> Indicator:
    return Indicator(
        id=id,
        category=category,
        title=title,
        description=description,
        evidence=evidence,
        severity=severity,
        score=score,
    )
