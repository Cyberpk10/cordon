"""Combination rule: a lure plus a delivery trick is worth more than the soft sum of its parts.

Runs after every single-signal rule (app.indicators.engine.run_indicators), over the findings
they produced, so it is still a pure, deterministic function of the email. It never fires
without a lure: a newsletter with a shortened tracking link has obfuscation but no lure and
gets nothing from here, which is what keeps ordinary mail clean.

- lure: SOCIAL_ENGINEERING_THEME, CREDENTIAL_REQUEST, PAYMENT_REQUEST, or URGENCY_LANGUAGE
  with at least two distinct pressure phrases (a lone "urgent" is too common to count)
- obfuscation: LINK_SHORTENER, LINK_DISPLAY_HREF_MISMATCH, LINK_IP_LITERAL, or any link to a
  hidden-destination host (shortener or file/document hosting,
  domain_utils.HIDDEN_DESTINATION_HOSTS)
- payload: a risky attachment finding
- hijacked sender: AUTHENTICATED_SENDER_CONTENT_MISMATCH (real institutional mail carrying it)

Bonus per group present with the lure: obfuscation +20, payload +25, hijacked sender +20,
summed and capped at +35; +10 more when the lure itself has two or more independent parts
(e.g. a credential ask under time pressure), capped at +45 in total.
"""

from __future__ import annotations

from app.channels.message import Message
from app.indicators.base import make_indicator
from app.indicators.domain_utils import is_hidden_destination_host
from app.models.schemas import Indicator, Severity

INDICATOR_ID = "LURE_COMBINATION"

OBFUSCATION_IDS = {"LINK_SHORTENER", "LINK_DISPLAY_HREF_MISMATCH", "LINK_IP_LITERAL"}
PAYLOAD_IDS = {
    "ATTACHMENT_RISKY_EXTENSION", "ATTACHMENT_DOUBLE_EXTENSION", "ATTACHMENT_MACRO_ENABLED",
    "ATTACHMENT_HTML", "ATTACHMENT_ARCHIVE_RISKY_CONTENT", "ATTACHMENT_ENCRYPTED_ARCHIVE",
    "ATTACHMENT_TYPE_MISMATCH",
}

HIJACKED_SENDER_IDS = {"AUTHENTICATED_SENDER_CONTENT_MISMATCH"}

_GROUP_BONUS = {"obfuscation": 20, "payload": 25, "hijacked": 20}
_MAX_BONUS = 35
_MULTI_LURE_BONUS = 10
_MAX_TOTAL = 45
_STRONG_URGENCY_MIN_SCORE = 8  # URGENCY_LANGUAGE scores 4 per distinct phrase
HIDDEN_LINK_EVIDENCE = "HIDDEN_DESTINATION_LINK"
_GROUP_PHRASE = {
    "obfuscation": "hidden link destinations",
    "payload": "a risky attachment",
    "hijacked": "a hijacked institutional sender",
}


def _lure_ids(by_id: dict[str, Indicator]) -> list[str]:
    lure = [i for i in ("SOCIAL_ENGINEERING_THEME", "CREDENTIAL_REQUEST", "PAYMENT_REQUEST") if i in by_id]
    urgency = by_id.get("URGENCY_LANGUAGE")
    if urgency is not None and urgency.score >= _STRONG_URGENCY_MIN_SCORE:
        lure.append("URGENCY_LANGUAGE")
    return lure


def _hidden_destination_hosts(email: Message | None) -> list[str]:
    if email is None:
        return []
    return sorted({l.href_domain for l in email.links if is_hidden_destination_host(l.href_domain)})


def evaluate(indicators: list[Indicator], email: Message | None = None) -> list[Indicator]:
    by_id = {i.id: i for i in indicators}
    lure = _lure_ids(by_id)
    if not lure:
        return []
    hidden_hosts = _hidden_destination_hosts(email)
    groups = {
        "obfuscation": sorted(OBFUSCATION_IDS & by_id.keys()),
        "payload": sorted(PAYLOAD_IDS & by_id.keys()),
        "hijacked": sorted(HIJACKED_SENDER_IDS & by_id.keys()),
    }
    present = [g for g, ids in groups.items() if ids or (g == "obfuscation" and hidden_hosts)]
    if not present:
        return []
    score = min(_MAX_BONUS, sum(_GROUP_BONUS[g] for g in present))
    if len(lure) >= 2:
        score = min(_MAX_TOTAL, score + _MULTI_LURE_BONUS)
    parts = ["a lure"] + [_GROUP_PHRASE[g] for g in present]
    contributing = [*lure, *(i for g in present for i in groups[g])]
    evidence = [f"{iid}: {by_id[iid].title}" for iid in contributing]
    if "obfuscation" in present and hidden_hosts:
        evidence.append(
            f"{HIDDEN_LINK_EVIDENCE}: link(s) via shortener or file-sharing host: {', '.join(hidden_hosts[:5])}"
        )
    return [
        make_indicator(
            id=INDICATOR_ID,
            category="combination",
            title="Lure combined with " + " and ".join(parts[1:]),
            description=(
                "Each of these signals is weak alone, but " + ", ".join(parts[:-1]) + " and " + parts[-1]
                + " together are the shape of a deliberate attack rather than ordinary mail."
            ),
            evidence=evidence,
            severity=Severity.HIGH,
            score=score,
        )
    ]
