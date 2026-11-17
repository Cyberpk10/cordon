"""Account takeover / compromised sender (Phase 1 identity detection).

A legitimate mailbox that has been taken over sends real, authenticated mail: SPF/DKIM/DMARC
pass because it IS the account, so authentication-based filtering waves it through. What's
left is behavioral: the sender acting unlike their own history. This rule compares the email
with the baseline for its exact From address (app.sender_baseline) and fires only when ALL of
these hold together:

  1. Established: the address has a trusted baseline for this account (enough prior clean,
     authenticated mail, over real time, and nothing malicious).
  2. Authenticated: this message passes as that sender (DMARC pass, or SPF+DKIM pass).
  3. A real anomaly against that baseline: a country never seen from the same IP source, a
     sending provider never seen, a new reply-to or return-path domain, or a strong timing
     outlier.
  4. A sensitive ask: a payment/bank-detail change or invoice redirect, a credential or MFA
     request, gift cards, or heavy pressure to act on a link or attachment.

An anomaly alone never fires (a new country is usually travel), and neither does a sensitive
ask alone from a known sender (that's normal business, and TRUSTED_SENDER_ANOMALY covers the
link-based variant). No baseline means no finding: first contact is never treated as ATO, and
a baseline is never invented.

When the sender's domain is one of the account's own domains, the finding is the lateral /
internal-phishing variant (a compromised colleague).

Distinct from LOOKALIKE_OF_KNOWN_SENDER: a look-alike domain is a different address with no
baseline of its own, so it can never reach this rule's condition 1.

Fully deterministic and offline; the explanation is built only from the baseline's own
numbers and the evidence matched here, never LLM text. The email stays data throughout.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from app.geo.countries import COUNTRY_NAMES
from app.indicators.base import make_indicator
from app.indicators.credential_payment import _CREDENTIAL_PATTERN
from app.indicators.trusted_sender_anomaly import _PAYMENT_CHANGE_PATTERN
from app.indicators.urgency_language import _PATTERN as _URGENCY_PATTERN
from app.models.schemas import Indicator, Severity
from app.channels.message import Channel, Message
from app.sender_baseline.aggregation import SenderBaseline, usual_countries, usual_providers
from app.sender_baseline.signals import MessageSignals, extract_signals
from app.sender_history.aggregation import SenderHistorySnapshot

EXTERNAL_ID = "ACCOUNT_TAKEOVER"
LATERAL_ID = "ACCOUNT_TAKEOVER_LATERAL"
EXTERNAL_SCORE = 45
LATERAL_SCORE = 50

# Timing outlier: needs a real history of send times, and a big gap from all of them.
TIMING_MIN_SAMPLES = 10
TIMING_MIN_GAP_HOURS = 4

_INVOICE_REDIRECT_PATTERN = re.compile(
    "|".join(
        f"(?:{p})"
        for p in [
            r"remit (?:payment |funds )?to",
            r"updated (?:invoice|remittance|banking|bank|payment) (?:details|information|instructions)",
            r"new (?:remittance|beneficiary)",
            r"(?:new|updated|changed) (?:account|banking) (?:details|information|number)",
            r"pay (?:the |this |our )?(?:outstanding )?invoice (?:to|into)",
            r"(?:send|make|direct) (?:the |all |future )?payments? to (?:our|the|this) new",
            r"wire (?:details|instructions)",
        ]
    ),
    re.IGNORECASE,
)
_MFA_PATTERN = re.compile(
    "|".join(
        f"(?:{p})"
        for p in [
            r"\b(?:mfa|2fa|two[- ]factor|multi[- ]factor)\b.{0,40}\b(?:code|approve|approval|prompt)",
            r"(?:verification|security|one[- ]time|sign[- ]?in|login) code",
            r"authenticator (?:app|code)",
            r"approve (?:the |this |my )?(?:sign[- ]?in|login|request|prompt|notification)",
            r"(?:send|share|forward|give|text) me (?:the|your|that) code",
        ]
    ),
    re.IGNORECASE,
)
_GIFT_CARD_PATTERN = re.compile(r"gift ?cards?", re.IGNORECASE)

_INTENT_TEXT = {
    "payment_change": "asks to change payment or bank details",
    "invoice_redirect": "redirects an invoice payment",
    "credential": "asks for login credentials",
    "mfa": "asks for an MFA or verification code",
    "gift_cards": "asks for gift cards",
    "urgent_action": "pressures you to act urgently on a link or attachment",
}


@dataclass(frozen=True)
class TakeoverAssessment:
    kind: str  # "external" | "lateral"
    explanation: str
    anomalies: list[str] = field(default_factory=list)
    intents: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "kind": self.kind,
            "explanation": self.explanation,
            "anomalies": list(self.anomalies),
            "intents": list(self.intents),
        }


def _country(code: str) -> str:
    return COUNTRY_NAMES.get(code, code)


def _circular_gap(hour: int, other: int) -> int:
    d = abs(hour - other) % 24
    return min(d, 24 - d)


def _anomalies(signals: MessageSignals, baseline: SenderBaseline) -> list[tuple[str, str]]:
    """(plain-English clause, evidence line) per anomaly found."""
    found: list[tuple[str, str]] = []

    if signals.sending_country and signals.country_source:
        seen = baseline.countries.get(signals.country_source, {})
        if seen and signals.sending_country not in seen:
            usual = ", ".join(_country(c) for c in usual_countries(baseline, signals.country_source))
            where = "originating client IP" if signals.country_source == "originating" else "sending server IP"
            found.append((
                f"was sent from {_country(signals.sending_country)} (the {where} {signals.sending_ip}; "
                f"this sender's mail normally comes from {usual})",
                f"New sending country: {_country(signals.sending_country)} via {signals.sending_ip} "
                f"({signals.country_source}); baseline: {usual}",
            ))

    if signals.sending_provider and baseline.providers and signals.sending_provider not in baseline.providers:
        usual = ", ".join(usual_providers(baseline))
        found.append((
            f"was sent through {signals.sending_provider} instead of this sender's usual {usual}",
            f"New sending provider: {signals.sending_provider}; baseline: {usual}",
        ))

    if (
        signals.reply_to_domain
        and signals.reply_to_domain != signals.from_domain
        and signals.reply_to_domain not in baseline.reply_to_domains
    ):
        found.append((
            f"sends replies to {signals.reply_to_domain}, a domain this sender has never used for replies",
            f"New reply-to domain: {signals.reply_to_domain} (From domain {signals.from_domain})",
        ))

    if (
        signals.return_path_domain
        and baseline.return_path_domains
        and signals.return_path_domain not in baseline.return_path_domains
    ):
        usual = ", ".join(sorted(baseline.return_path_domains)[:3])
        found.append((
            f"has a bounce address (Return-Path) at {signals.return_path_domain}, never seen for this "
            f"sender (usually {usual})",
            f"New return-path domain: {signals.return_path_domain}; baseline: {usual}",
        ))

    hour = signals.message_hour_utc
    if hour is not None and len(baseline.hours) >= TIMING_MIN_SAMPLES:
        gap = min(_circular_gap(hour, h) for h in baseline.hours)
        if gap >= TIMING_MIN_GAP_HOURS:
            found.append((
                f"was sent at {hour:02d}:00 UTC, at least {gap} hours from any time this sender has "
                f"sent before ({len(baseline.hours)} messages on record)",
                f"Timing outlier: {hour:02d}:00 UTC, {gap}h from every prior send time",
            ))
    return found


def _intents(email: Message) -> list[tuple[str, str]]:
    """(intent key, evidence line) per sensitive ask found."""
    text = " ".join(filter(None, [email.subject, email.body_text]))
    found: list[tuple[str, str]] = []

    # The shared payment-change pattern also matches "gift cards"; that's reported below.
    payment = next(
        (m for m in _PAYMENT_CHANGE_PATTERN.finditer(text) if not _GIFT_CARD_PATTERN.fullmatch(m.group(0).strip())),
        None,
    )
    if payment:
        found.append(("payment_change", f"Payment-change request: {payment.group(0).strip()!r}"))
    invoice = _INVOICE_REDIRECT_PATTERN.search(text)
    if invoice:
        found.append(("invoice_redirect", f"Invoice redirect: {invoice.group(0).strip()!r}"))
    credential = _CREDENTIAL_PATTERN.search(text)
    if credential:
        found.append(("credential", f"Credential request: {credential.group(0).strip()!r}"))
    mfa = _MFA_PATTERN.search(text)
    if mfa:
        found.append(("mfa", f"MFA/verification-code request: {mfa.group(0).strip()!r}"))
    gift = _GIFT_CARD_PATTERN.search(text)
    if gift:
        found.append(("gift_cards", f"Gift-card request: {gift.group(0).strip()!r}"))

    # Urgency only counts as heavy pressure tied to something to act on: two or more
    # distinct pressure phrases AND a link or attachment. A single "please review by EOD"
    # from a travelling colleague must not count.
    urgency = sorted({m.group(0).strip().lower() for m in _URGENCY_PATTERN.finditer(text)})
    if len(urgency) >= 2 and (email.links or email.attachments):
        found.append(("urgent_action", "High-pressure language with a link/attachment: " + ", ".join(urgency)))
    return found


def _join(clauses: list[str]) -> str:
    if len(clauses) <= 1:
        return "".join(clauses)
    return ", ".join(clauses[:-1]) + " and " + clauses[-1]


def assess(email: Message, history: SenderHistorySnapshot | None) -> TakeoverAssessment | None:
    """The whole decision, pure. None unless all four conditions hold."""
    if email.channel != Channel.EMAIL or history is None:
        return None
    baseline = history.sender_baseline
    if baseline is None or baseline.status != "established":
        return None
    signals = extract_signals(email)
    if signals is None or signals.from_addr != baseline.from_addr or not signals.auth_pass:
        return None

    anomalies = _anomalies(signals, baseline)
    if not anomalies:
        return None
    intents = _intents(email)
    if not intents:
        return None

    lateral = signals.from_domain in history.account_domains
    usual = [_country(c) for c in usual_countries(baseline)]
    providers = usual_providers(baseline)
    profile = [f"{baseline.message_count} prior messages since {baseline.first_seen:%b} {baseline.first_seen.day}"]
    if usual:
        profile.append("normally from " + ", ".join(usual))
    if providers:
        profile.append("via " + ", ".join(providers))
    profile.append(f"authentication passed on {baseline.auth_pass_count} of {baseline.message_count}")
    if baseline.malicious_count:
        profile.append(f"{baseline.malicious_count} recent message(s) already flagged malicious")

    who = "Known colleague" if lateral else "Known sender"
    conclusion = (
        "consistent with a colleague's account being compromised and used for internal phishing"
        if lateral
        else "consistent with a compromised account"
    )
    explanation = (
        f"{who} {signals.from_addr} ({'; '.join(profile)}) authenticated correctly, but this message "
        f"{_join([a[0] for a in anomalies])}, and it {_join([_INTENT_TEXT[k] for k, _ in intents])}: "
        f"{conclusion}."
    )
    evidence = (
        [f"Sender: {signals.from_addr} ({'own organisation' if lateral else 'external'})",
         f"Baseline: {'; '.join(profile)}",
         "Authentication: passed as this sender"]
        + [a[1] for a in anomalies]
        + [i[1] for i in intents]
    )
    return TakeoverAssessment(
        kind="lateral" if lateral else "external",
        explanation=explanation,
        anomalies=[a[1] for a in anomalies],
        intents=[k for k, _ in intents],
        evidence=evidence,
    )


def evaluate(email: Message, sender_history: SenderHistorySnapshot | None = None) -> list[Indicator]:
    result = assess(email, sender_history)
    if result is None:
        return []
    if result.kind == "lateral":
        return [make_indicator(
            id=LATERAL_ID,
            category="sender",
            title="Internal phishing from a likely compromised colleague",
            description=result.explanation,
            evidence=result.evidence,
            severity=Severity.HIGH,
            score=LATERAL_SCORE,
        )]
    return [make_indicator(
        id=EXTERNAL_ID,
        category="sender",
        title="Likely account takeover: a known sender acting out of pattern",
        description=result.explanation,
        evidence=result.evidence,
        severity=Severity.HIGH,
        score=EXTERNAL_SCORE,
    )]
