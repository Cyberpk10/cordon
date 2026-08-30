"""Per-account sender-history-aware indicators (M8 Stage 3a) — closes phase-2 red-team
scenarios 1 and 5 (uncurated-brand and B2B-vendor-impersonation phishing, both invisible to
lookalike_domain.py's curated 16-brand list and to urgency_language.py/credential_payment.py's
fixed phrase banks, which a calm, professionally-written lure with no urgency language simply
never matches). Every check here compares the sending domain against THIS ACCOUNT's own past
correspondence (app.sender_history.aggregation), never against brands.yaml — a distinct,
complementary signal to the existing curated-brand lookalike check, not a replacement for it.
Self-guards on `email.channel != Channel.EMAIL` — chat sender reputation is out of scope for
this stage."""

from __future__ import annotations

import re

from app.indicators.base import make_indicator
from app.indicators.domain_utils import levenshtein, registrable_domain
from app.models.schemas import Indicator, Severity
from app.channels.message import Channel, Message
from app.sender_history.aggregation import (
    SenderClassification,
    SenderHistorySnapshot,
    classify_sender,
    established_domains,
)

_MAX_LOOKALIKE_DISTANCE = 2

# Phrases that claim an existing business/vendor relationship — deliberately broader than
# literal invoice/BEC language (credential_payment.py's PAYMENT_REQUEST already covers
# "outstanding invoice"-style wire-fraud phrasing) to also catch the fake-SaaS-notification
# and fake-vendor-portal framing real B2B-impersonation lures use ("your quarterly vendor
# access review", "as part of our ongoing review").
_VENDOR_RELATIONSHIP_PHRASES = [
    r"as (?:we )?discussed",
    r"per our (?:conversation|call|email|discussion)",
    r"further to (?:our|my) (?:previous |last )?(?:email|conversation|call)",
    r"following up on (?:our|my|the )?(?:invoice|conversation|previous email|last email)",
    r"as (?:per|agreed)(?: our| in)? agreement",
    r"our (?:ongoing|existing) (?:partnership|relationship|engagement)",
    r"as (?:a |your )?(?:valued |trusted )?(?:vendor|partner|supplier|client|customer)",
    r"(?:outstanding|attached|your) invoice",
    r"renewing (?:your|our) (?:subscription|contract|agreement|service)",
    r"(?:contract|subscription) renewal",
    r"vendor (?:access |account )?review",
    r"(?:quarterly|annual) (?:business )?review",
    r"as part of (?:a |this |our )?(?:broader |wider |ongoing |annual )?review",
    r"part of (?:this|our|the) (?:review )?cycle",
    r"your (?:recent|last) (?:order|purchase|payment)",
    r"as your (?:account manager|service provider)",
]
_VENDOR_PATTERN = re.compile("|".join(f"(?:{p})" for p in _VENDOR_RELATIONSHIP_PHRASES), re.IGNORECASE)


def _sender_domain(email: Message) -> str | None:
    if not email.from_address or "@" not in email.from_address:
        return None
    return registrable_domain(email.from_address.rsplit("@", 1)[-1].lower())


def _lookalike_match(domain: str, known: set[str]) -> tuple[str, int] | None:
    if domain in known:
        return None  # exact match to a known sender is not a look-alike, it IS the sender
    closest = min(((k, levenshtein(domain, k)) for k in known), key=lambda p: p[1], default=None)
    if closest and 0 < closest[1] <= _MAX_LOOKALIKE_DISTANCE:
        return closest
    return None


def evaluate(
    email: Message, sender_history: SenderHistorySnapshot | None = None
) -> list[Indicator]:
    if email.channel != Channel.EMAIL:
        return []

    history = sender_history
    domain = _sender_domain(email)
    if not domain or history is None:
        return []

    indicators: list[Indicator] = []

    # --- LOOKALIKE_OF_KNOWN_SENDER: checked regardless of this domain's own classification.
    known = established_domains(history)
    match = _lookalike_match(domain, known)
    if match:
        known_domain, distance = match
        indicators.append(
            make_indicator(
                id="LOOKALIKE_OF_KNOWN_SENDER",
                category="sender",
                title="Look-alike of a domain this account regularly corresponds with",
                description=(
                    f"The sending domain '{domain}' is a near-exact match (edit distance "
                    f"{distance}) of '{known_domain}', a domain this account has an established "
                    "correspondence history with — a common technique for impersonating a "
                    "known vendor, partner, or colleague rather than a generic public brand."
                ),
                evidence=[f"Sending domain: {domain}", f"Mimics known correspondent: {known_domain}"],
                severity=Severity.HIGH,
                score=30,
            )
        )
        # A confirmed look-alike is a distinct, higher-confidence finding from plain
        # first-contact/vendor-claim — don't also pad the score with those below for the
        # same email; the look-alike indicator alone carries the full signal here.
        return indicators

    classification = classify_sender(history, domain)
    if classification != SenderClassification.FIRST_CONTACT:
        return indicators

    # --- FIRST_CONTACT_SENDER
    indicators.append(
        make_indicator(
            id="FIRST_CONTACT_SENDER",
            category="sender",
            title="First contact from this sender",
            description=(
                f"This is the first email this account has received from '{domain}' in the "
                "analyzed history window. Not suspicious on its own — most legitimate first "
                "contacts look exactly like this — but combined with other signals it raises "
                "confidence that a claimed business relationship doesn't actually exist yet."
            ),
            evidence=[f"Sending domain: {domain}"],
            severity=Severity.LOW,
            score=8,
        )
    )

    # --- UNKNOWN_VENDOR_CLAIM: only meaningful paired with FIRST_CONTACT above — the
    # combination (not either alone) is the actual signal.
    text = " ".join(filter(None, [email.subject, email.body_text]))
    matches = sorted({m.group(0).strip().lower() for m in _VENDOR_PATTERN.finditer(text)})
    if matches:
        score = min(28, 19 + 5 * (len(matches) - 1))
        indicators.append(
            make_indicator(
                id="UNKNOWN_VENDOR_CLAIM",
                category="content",
                title="Claims a vendor/business relationship with no correspondence history",
                description=(
                    "The message uses language implying an existing business or vendor "
                    "relationship (e.g. a prior conversation, invoice, or recurring review), "
                    f"but '{domain}' has no prior correspondence with this account — a common "
                    "framing for supply-chain and vendor-impersonation phishing that doesn't "
                    "impersonate a well-known consumer brand."
                ),
                evidence=[f"Matched phrase: {m!r}" for m in matches],
                severity=Severity.MEDIUM,
                score=score,
            )
        )

    return indicators
