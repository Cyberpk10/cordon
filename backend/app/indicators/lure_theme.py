"""Deterministic social-engineering lure themes: romance/adult dating, sextortion, prize/
inheritance, and crypto-investment bait, from fixed phrase banks over subject and body.

Deliberately low weight on its own (a theme is a topic, not proof of malice: plenty of spam
is merely annoying). It matters in combination: app.indicators.combinations escalates when a
lure theme co-occurs with obfuscated links or a risky attachment, and
app.indicators.institutional_sender_mismatch uses it to spot hijacked institutional accounts.
Phrases are specific on purpose so ordinary business and newsletter mail doesn't match.
"""

from __future__ import annotations

import re

from app.channels.message import Message
from app.indicators.base import make_indicator
from app.models.schemas import Indicator, Severity
from app.sender_history.aggregation import SenderHistorySnapshot

THEME_PHRASES: dict[str, list[str]] = {
    "romance": [
        r"casual (?:dating|sex|encounters?|fun|relationship)",
        r"adult dating",
        r"dating (?:site|profile|app) (?:for|with) (?:singles|adults)",
        r"casual hook-?ups?\b",
        r"hook-?up (?:site|app|partner|tonight)",
        r"(?:lonely|horny|naughty) (?:girls?|women|wives|housewives|milfs?|singles?)",
        r"(?:i'?m|i am) (?:so )?(?:lonely|horny)",
        r"single (?:women|girls|ladies|moms|milfs) (?:near|in|around) (?:you|your)",
        r"(?:see|view|check out) my (?:private|hot|sexy|naked|intimate) (?:photos?|pics?|pictures|videos?|profile)",
        r"my (?:private|sexy|naked|intimate) (?:photos?|pics?|pictures|videos?)",
        r"looking for (?:a )?(?:man|men|guy|partner) (?:for|to) (?:fun|tonight|sex|dating)",
        r"sexy (?:girls?|women|singles|chat)",
        r"\bsex ?dating\b",
    ],
    "sextortion": [
        r"\bi(?:'ve| have)? recorded you",
        r"(?:hacked|infected|compromised) your (?:device|computer|phone|webcam|camera)",
        r"your (?:device|computer|phone) (?:was|has been) (?:hacked|infected|compromised)",
        r"(?:video|recording) of you (?:while )?(?:watching|masturbating|pleasuring)",
        r"(?:send|share|forward) (?:the )?(?:video|recording) to (?:all )?your contacts",
        r"pay (?:me )?(?:in )?(?:bitcoin|btc|crypto)",
        r"(?:bitcoin|btc) (?:wallet|address)[^.\n]{0,60}(?:48|24|72) hours",
    ],
    "prize": [
        r"you(?:'ve| have) won (?:a |an |the )?(?:cash|lottery|prize|sum|jackpot|iphone|gift card|\$|€|£|usd)",
        r"claim your (?:prize|winnings|lottery|jackpot|inheritance)",
        r"(?:lottery|sweepstakes?|jackpot) (?:winner|award|prize|draw)",
        r"(?:winning|lucky) (?:ticket|number|email)",
        r"(?:unclaimed|inheritance) (?:funds|fund|sum|estate|payment)",
        r"(?:next of kin|beneficiary) (?:of|to) (?:the )?(?:late|deceased|fund|estate|sum)",
        r"(?:sum|amount) of (?:usd|us\$|\$|€|£)\s?[\d,.]+ (?:million|m)\b",
    ],
    "crypto_investment": [
        r"double your (?:bitcoin|btc|crypto|money|investment)",
        r"(?:crypto|bitcoin|forex) (?:trading )?(?:investment|opportunity) (?:with|of) (?:\d+%|guaranteed)",
        r"earn \$?[\d,]+ (?:daily|per day|a day) (?:from|with|trading)",
    ],
}

_PATTERNS = {theme: re.compile("|".join(f"(?:{p})" for p in phrases), re.IGNORECASE) for theme, phrases in THEME_PHRASES.items()}

INDICATOR_ID = "SOCIAL_ENGINEERING_THEME"
_LABELS = {
    "romance": "romance / adult dating",
    "sextortion": "sextortion",
    "prize": "prize / inheritance",
    "crypto_investment": "crypto-investment bait",
}


def detect_themes(email: Message) -> dict[str, list[str]]:
    """{theme: sorted unique matched phrases}. Shared with institutional_sender_mismatch."""
    text = " ".join(filter(None, [email.subject, email.body_text]))
    found: dict[str, list[str]] = {}
    for theme, pattern in _PATTERNS.items():
        matches = sorted({m.group(0).strip().lower() for m in pattern.finditer(text)})
        if matches:
            found[theme] = matches
    return found


def evaluate(email: Message, sender_history: SenderHistorySnapshot | None = None) -> list[Indicator]:
    themes = detect_themes(email)
    if not themes:
        return []
    evidence = [
        f"{_LABELS[theme]}: {', '.join(repr(p) for p in phrases[:4])}" for theme, phrases in themes.items()
    ]
    return [
        make_indicator(
            id=INDICATOR_ID,
            category="content",
            title="Social-engineering lure theme",
            description=(
                "The message uses a classic lure theme (" + ", ".join(_LABELS[t] for t in themes) + "). "
                "On its own this is a weak signal; it becomes strong together with hidden links, "
                "risky attachments or an unexpected sender."
            ),
            evidence=evidence,
            severity=Severity.LOW,
            score=8,
        )
    ]
