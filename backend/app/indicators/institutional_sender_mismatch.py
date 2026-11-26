"""Hijacked-institutional-account tell: mail that really did come from a university, school
or government domain (SPF or DKIM pass) but carries content no institution sends (romance/
adult dating, sextortion, prize/inheritance, crypto-investment bait).

Authentication proves the mail left that domain's servers, so it isn't spoofing; the content
proves the sender isn't acting for the institution. Together that's the signature of a
compromised student/staff mailbox being used as a trusted relay. Generic payment, deadline or
urgency language is deliberately NOT enough here: institutions really do send "outstanding
balance" and "registration closes Friday" mail. Unauthenticated mail is left to the
auth-failure and spoofing rules.
"""

from __future__ import annotations

import re

from app.channels.message import Message
from app.indicators.base import make_indicator
from app.indicators.lure_theme import _LABELS, detect_themes
from app.models.schemas import AuthResultValue, Indicator, Severity
from app.sender_history.aggregation import SenderHistorySnapshot

INDICATOR_ID = "AUTHENTICATED_SENDER_CONTENT_MISMATCH"

# Institutions legitimately quote scam wording in security-awareness mail ("scammers will ask
# you to pay in bitcoin"). Such mail names the threat; a real lure never does.
_AWARENESS_RE = re.compile(
    r"\b(?:phishing|scams?|scammers?|fraud(?:sters?|ulent)?|security awareness|"
    r"report (?:it|suspicious|this)|do not (?:respond|reply|click)|beware)\b",
    re.IGNORECASE,
)

_INSTITUTIONAL_TLDS = {"edu", "gov", "mil"}
_INSTITUTIONAL_SECOND_LEVELS = {"edu", "gov", "gob", "govt", "ac", "go", "k12", "mil", "sch", "nhs"}


def institutional_kind(domain: str | None) -> str | None:
    """'education' / 'government' for an institutional domain, else None."""
    if not domain:
        return None
    labels = domain.lower().strip(".").split(".")
    if len(labels) < 2:
        return None
    candidates = [labels[-1]]
    if len(labels) >= 3:
        candidates.append(labels[-2])
    if "k12" in labels:
        return "education"
    for label in candidates:
        is_tld = label == labels[-1]
        if (is_tld and label in _INSTITUTIONAL_TLDS) or (not is_tld and label in _INSTITUTIONAL_SECOND_LEVELS):
            return "education" if label in {"edu", "ac", "k12", "sch"} else "government"
    return None


def evaluate(email: Message, sender_history: SenderHistorySnapshot | None = None) -> list[Indicator]:
    address = (email.from_address or "").strip().lower()
    if "@" not in address:
        return []
    domain = address.rsplit("@", 1)[1]
    kind = institutional_kind(domain)
    if kind is None:
        return []
    auth = email.auth_results
    if auth.spf != AuthResultValue.PASS and auth.dkim != AuthResultValue.PASS:
        return []
    themes = detect_themes(email)
    if not themes:
        return []
    if _AWARENESS_RE.search(" ".join(filter(None, [email.subject, email.body_text]))):
        return []
    passed = [name for name, value in (("SPF", auth.spf), ("DKIM", auth.dkim)) if value == AuthResultValue.PASS]
    return [
        make_indicator(
            id=INDICATOR_ID,
            category="sender",
            title="Authentic institutional sender, content it wouldn't send",
            description=(
                f"This message genuinely came from a {kind} domain ({domain}; {' and '.join(passed)} "
                "passed), but its content is something that institution would not send. That "
                "combination usually means a student or staff mailbox there has been taken over "
                "and is being used to borrow the institution's reputation."
            ),
            evidence=[
                f"Sender domain: {domain} ({kind})",
                f"Authentication passed: {', '.join(passed)}",
                *[f"Content theme: {_LABELS[t]} ({', '.join(repr(p) for p in phrases[:3])})" for t, phrases in themes.items()],
            ],
            severity=Severity.HIGH,
            score=30,
        )
    ]
