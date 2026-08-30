"""Zero-network proxy for "this domain looks newly/cheaply registered" (M8 Stage 3a) — NOT a
real WHOIS/RDAP registration-age check. This codebase's email analyzer deliberately makes no
outbound network/DNS calls during analysis (see app.parsing.eml_parser's module docstring;
app.simulation.dns_check's one exception is explicitly scoped to proving domain control for
phishing-simulation targeting, not a precedent for the analyzer itself) — a real registration
date would require a live lookup, so this is a heuristic substitute instead. Substantially
overlaps with app.indicators.link_analysis's LINK_SUSPICIOUS_TLD (cheap TLDs are
disproportionately used for short-lived attacker infrastructure precisely because they're
cheap to register in bulk); kept as a separate, lower-weight indicator ID so the two can be
told apart in evidence, not because they measure independent things.
"""

from __future__ import annotations

import math
from collections import Counter

from app.core.config import settings
from app.indicators.base import make_indicator
from app.indicators.domain_utils import registrable_domain
from app.channels.message import Message
from app.models.schemas import Indicator, Severity
from app.sender_history.aggregation import SenderHistorySnapshot

_MIN_LABEL_LENGTH_FOR_ENTROPY_CHECK = 8


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def evaluate(
    email: Message, sender_history: SenderHistorySnapshot | None = None
) -> list[Indicator]:
    if not settings.enable_newly_registered_domain_heuristic:
        return []
    if not email.from_address or "@" not in email.from_address:
        return []

    domain = registrable_domain(email.from_address.rsplit("@", 1)[-1].lower())
    label = domain.split(".")[0]
    if len(label) < _MIN_LABEL_LENGTH_FOR_ENTROPY_CHECK:
        return []

    entropy = _shannon_entropy(label)
    has_digit_letter_mix = any(c.isdigit() for c in label) and any(c.isalpha() for c in label)
    if entropy < settings.newly_registered_domain_entropy_threshold or not has_digit_letter_mix:
        return []

    return [
        make_indicator(
            id="DOMAIN_LOOKS_RANDOMLY_GENERATED",
            category="domain",
            title="Sending domain name looks randomly generated",
            description=(
                f"The domain label '{label}' has unusually high character-entropy and mixes "
                "letters and digits in a pattern more consistent with an automatically "
                "generated or freshly-registered domain than a real organization's brand name. "
                "This is a zero-network heuristic proxy, not a verified WHOIS/RDAP registration "
                "date."
            ),
            evidence=[f"Domain: {domain}", f"Entropy: {entropy:.2f}"],
            severity=Severity.MEDIUM,
            score=10,
        )
    ]
