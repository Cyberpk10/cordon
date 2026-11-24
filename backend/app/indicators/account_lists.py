"""The account's own in-Cordon watchlist/blocklist (D5).

Entries are added by the graduated-autonomy engine's reversible L2 actions
(app.autonomy.cordon_actions) or by a person, and removed by undo. A blocklisted sender address
or domain is weighted like a threat-intel domain hit (SENDER_DOMAIN_KNOWN_BAD); a watched
sender, domain or sending IP adds an informational, zero-point finding so an analyst sees the
history. Everything is per account and inside Cordon: nothing here blocks mail anywhere.
"""

from __future__ import annotations

from app.channels.message import Message
from app.indicators.base import make_indicator
from app.indicators.domain_utils import registrable_domain
from app.models.schemas import Indicator, Severity
from app.parsing.auth_results import extract_spf_client_ip
from app.sender_history.aggregation import SenderHistorySnapshot

BLOCKLIST_SCORE = 60  # same weight as SENDER_DOMAIN_KNOWN_BAD


def evaluate(email: Message, sender_history: SenderHistorySnapshot | None = None) -> list[Indicator]:
    lists = sender_history.account_lists if sender_history is not None else frozenset()
    if not lists:
        return []
    address = (email.from_address or "").strip().lower()
    domain = registrable_domain(address.rsplit("@", 1)[-1]) if "@" in address else None
    ip = None
    if email.auth_results is not None:
        ip = extract_spf_client_ip(email.auth_results.raw_header)

    candidates = [("sender", address), ("domain", domain), ("ip", ip)]
    blocked = [(k, v) for k, v in candidates if v and ("block", k, v) in lists]
    watched = [(k, v) for k, v in candidates if v and ("watch", k, v) in lists]

    out: list[Indicator] = []
    if blocked:
        out.append(make_indicator(
            id="ACCOUNT_BLOCKLIST_MATCH",
            category="sender",
            title="Sender is on this account's Cordon blocklist",
            description=(
                "This account's Cordon blocklist includes the sender. Entries come from an earlier "
                "high-confidence detection or from a person, and can be removed under Autonomy."
            ),
            evidence=[f"{k}: {v}" for k, v in blocked],
            severity=Severity.HIGH,
            score=BLOCKLIST_SCORE,
        ))
    if watched:
        out.append(make_indicator(
            id="ACCOUNT_WATCHLIST_MATCH",
            category="sender",
            title="Sender is on this account's Cordon watchlist",
            description="Earlier mail from this sender was flagged. Informational only: adds no points.",
            evidence=[f"{k}: {v}" for k, v in watched],
            severity=Severity.LOW,
            score=0,
        ))
    return out
