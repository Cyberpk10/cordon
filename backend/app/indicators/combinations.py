"""Combination rule: a lure plus a delivery trick is worth more than the soft sum of its parts.

Runs after every single-signal rule (app.indicators.engine.run_indicators), over the findings
they produced, so it is still a pure, deterministic function of the email. It never fires
without a lure: a newsletter with a shortened tracking link has obfuscation but no lure and
gets nothing from here, which is what keeps ordinary mail clean.

- lure: SOCIAL_ENGINEERING_THEME, or PAYMENT_REQUEST together with URGENCY_LANGUAGE
- obfuscation: LINK_SHORTENER, LINK_DISPLAY_HREF_MISMATCH, LINK_IP_LITERAL
- payload: a risky attachment finding
- hijacked sender: AUTHENTICATED_SENDER_CONTENT_MISMATCH (real institutional mail carrying it)

Bonus per group present with the lure: obfuscation +20, payload +25, hijacked sender +20,
summed and capped at +35.
"""

from __future__ import annotations

from app.indicators.base import make_indicator
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
_GROUP_PHRASE = {
    "obfuscation": "hidden link destinations",
    "payload": "a risky attachment",
    "hijacked": "a hijacked institutional sender",
}


def evaluate(indicators: list[Indicator]) -> list[Indicator]:
    by_id = {i.id: i for i in indicators}
    lure = []
    if "SOCIAL_ENGINEERING_THEME" in by_id:
        lure.append("SOCIAL_ENGINEERING_THEME")
    if "PAYMENT_REQUEST" in by_id and "URGENCY_LANGUAGE" in by_id:
        lure += ["PAYMENT_REQUEST", "URGENCY_LANGUAGE"]
    if not lure:
        return []
    groups = {
        "obfuscation": sorted(OBFUSCATION_IDS & by_id.keys()),
        "payload": sorted(PAYLOAD_IDS & by_id.keys()),
        "hijacked": sorted(HIJACKED_SENDER_IDS & by_id.keys()),
    }
    present = [g for g, ids in groups.items() if ids]
    if not present:
        return []
    score = min(_MAX_BONUS, sum(_GROUP_BONUS[g] for g in present))
    parts = ["a lure"] + [_GROUP_PHRASE[g] for g in present]
    contributing = [*lure, *(i for g in present for i in groups[g])]
    return [
        make_indicator(
            id=INDICATOR_ID,
            category="combination",
            title="Lure combined with " + " and ".join(parts[1:]),
            description=(
                "Each of these signals is weak alone, but " + ", ".join(parts[:-1]) + " and " + parts[-1]
                + " together are the shape of a deliberate attack rather than ordinary mail."
            ),
            evidence=[f"{iid}: {by_id[iid].title}" for iid in contributing],
            severity=Severity.HIGH,
            score=score,
        )
    ]
