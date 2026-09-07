"""Trusted-sender content anomaly (Cordon detection max-out, Stage A) — closes Phase 4
red-team scenario 3 (a compromised, previously-contacted sender). Stage 3a's
FIRST_CONTACT_SENDER/UNKNOWN_VENDOR_CLAIM checks are gated on true first contact
(app.sender_history.aggregation.SenderClassification.FIRST_CONTACT) — once a domain has had
ANY prior contact at all (even a single innocuous email, "SEEN_BEFORE", well short of the
fuller "regular correspondent" ESTABLISHED bar), those checks permanently stop scrutinizing
that sender's content. This module is the deliberate complement: it scrutinizes content from
senders the account already knows, specifically for the pattern a compromised trusted mailbox
actually produces — a genuinely high-risk ask (credential harvesting, or a payment/bank-detail
change) corroborated by something a legitimate sender's own history wouldn't produce.

Distinct from LOOKALIKE_OF_KNOWN_SENDER (app.indicators.sender_history): that fires on a
DIFFERENT domain resembling a known one. This fires on the EXACT known domain itself sending
anomalous content — a clean, non-overlapping split.

Fully deterministic and offline, same as every other indicator in this package. No new ML/LLM
wiring: app.ml.classifier's bounded nudge and app.reasoning.llm_analyst's post-fuse narrative
already apply naturally once this fires, without needing to restructure the pipeline's
indicator/ML/LLM ordering (ML runs after indicators, using them as input features, so it
cannot feed into this indicator's own decision without a materially bigger change than this
stage; the LLM narrative only ever explains an already-final score, never recomputes it).
"""

from __future__ import annotations

import re

from app.indicators.base import make_indicator
from app.indicators.credential_payment import _CREDENTIAL_PATTERN
from app.indicators.domain_utils import looks_randomly_generated, registrable_domain
from app.indicators.urgency_language import _PATTERN as _URGENCY_PATTERN
from app.models.schemas import Indicator, Severity
from app.channels.message import Channel, Message
from app.sender_history.aggregation import (
    SenderClassification,
    SenderHistorySnapshot,
    classify_sender,
)

_ENTROPY_THRESHOLD_FOR_LINKS = 3.0

# Deliberately NARROWER than credential_payment.py's _PAYMENT_PHRASES — excludes routine
# invoice/billing mentions ("outstanding invoice", "invoice attached...pay") on purpose,
# since a known vendor's ordinary billing correspondence must stay safe. Only phrases about
# CHANGING the payment mechanism itself, which no legitimate vendor asks for out of the blue.
_PAYMENT_CHANGE_PHRASES = [
    r"bank (?:account|routing) (?:number|details)",
    r"update your (?:direct deposit|banking) (?:information|details)",
    r"change of (?:bank|payment) (?:details|information)",
    r"new (?:bank|payment) (?:account|details)",
    r"wire transfer",
    r"gift cards?",
]
_PAYMENT_CHANGE_PATTERN = re.compile(
    "|".join(f"(?:{p})" for p in _PAYMENT_CHANGE_PHRASES), re.IGNORECASE
)


def _sender_domain(email: Message) -> str | None:
    if not email.from_address or "@" not in email.from_address:
        return None
    return registrable_domain(email.from_address.rsplit("@", 1)[-1].lower())


def evaluate(
    email: Message, sender_history: SenderHistorySnapshot | None = None
) -> list[Indicator]:
    if email.channel != Channel.EMAIL:
        return []

    history = sender_history
    domain = _sender_domain(email)
    if not domain or history is None:
        return []

    # Only scrutinizes senders the account has had SOME prior contact with — true first
    # contact is FIRST_CONTACT_SENDER/UNKNOWN_VENDOR_CLAIM's job (app.indicators.
    # sender_history), not this module's. Deliberately includes SEEN_BEFORE (a single prior
    # email), not just the fuller ESTABLISHED bar — that's the exact Phase 4 gap this closes.
    if classify_sender(history, domain) == SenderClassification.FIRST_CONTACT:
        return []

    text = " ".join(filter(None, [email.subject, email.body_text]))
    credential_match = _CREDENTIAL_PATTERN.search(text)
    payment_change_match = _PAYMENT_CHANGE_PATTERN.search(text)
    if not credential_match and not payment_change_match:
        return []

    trusted_domains = set(history.trusted_vendor_domains) | {domain}
    off_pattern_links: list[str] = []
    random_looking_links: list[str] = []
    for link in email.links:
        if not link.href_domain:
            continue
        link_domain = registrable_domain(link.href_domain.lower())
        if link_domain in trusted_domains:
            continue
        off_pattern_links.append(link_domain)
        label = link_domain.split(".")[0]
        if looks_randomly_generated(label, entropy_threshold=_ENTROPY_THRESHOLD_FOR_LINKS):
            random_looking_links.append(link_domain)

    urgency_matches = sorted({m.group(0).strip().lower() for m in _URGENCY_PATTERN.finditer(text)})

    corroborators: list[str] = []
    if off_pattern_links:
        corroborators.append(f"link(s) to unfamiliar domain(s): {', '.join(sorted(set(off_pattern_links)))}")
    if random_looking_links:
        corroborators.append(f"link(s) to randomly-generated-looking domain(s): {', '.join(sorted(set(random_looking_links)))}")

    # Credential asks require a link-domain anomaly specifically — legitimate transactional
    # security email ("verify your account", password resets) routinely includes time-boxed
    # urgency language, so urgency alone is not safe corroboration for this ask type.
    # Payment/bank-detail-change asks may additionally be corroborated by urgency alone: a
    # real vendor essentially never pairs "act now" with "here's our new bank account" — that
    # combination alone is a strong BEC signal.
    has_valid_corroboration = bool(off_pattern_links or random_looking_links)
    if payment_change_match and urgency_matches:
        corroborators.append(f"urgency/pressure language: {', '.join(urgency_matches)}")
        has_valid_corroboration = True

    if not has_valid_corroboration or not corroborators:
        return []

    ask_kind = "payment/bank-detail-change" if payment_change_match else "credential"
    score = min(50, 30 + 5 * len(corroborators))

    return [
        make_indicator(
            id="TRUSTED_SENDER_ANOMALY",
            category="content",
            title="Anomalous high-risk request from a known sender",
            description=(
                f"'{domain}' is a sender this account has had prior contact with, but this "
                f"message makes a {ask_kind} request — something this sender's own history "
                "gives no reason to expect — corroborated by "
                f"{'; '.join(corroborators)}. Consistent with a legitimate mailbox that has "
                "since been compromised, rather than an evasive first-contact phish."
            ),
            evidence=[f"Sender domain: {domain}"] + corroborators,
            severity=Severity.HIGH,
            score=score,
        )
    ]
