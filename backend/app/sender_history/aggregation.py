"""Pure aggregation math for per-account sender-correspondence history (M8 Stage 3a). No
DB/SQLAlchemy here — same separation as app.baselines.aggregation. SenderHistorySnapshot is a
DB-free read view of an account's own past Case rows (plus an optional customer-supplied
trusted-vendor allowlist), built by app.sender_history.loader and passed down through
app.indicators.engine.run_indicators to every indicator rule.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

from app.core.config import settings
from app.indicators.domain_utils import registrable_domain


@dataclass(frozen=True)
class DomainHistory:
    domain: str
    seen_count: int
    first_seen: datetime
    last_seen: datetime


class SenderClassification(str, Enum):
    ESTABLISHED = "established"      # a regular correspondent, or an explicit trusted vendor
    SEEN_BEFORE = "seen_before"      # appeared in history, but not (yet) a stable pattern
    FIRST_CONTACT = "first_contact"  # never seen before, and not an explicit trusted vendor


@dataclass(frozen=True)
class SenderHistorySnapshot:
    # Keyed by registrable domain (app.indicators.domain_utils.registrable_domain), built
    # from this account's own past Case.from_addr values — never from brands.yaml or any
    # other account's data.
    domains: dict[str, DomainHistory] = field(default_factory=dict)
    # Customer-supplied allowlist (app.db.models.TrustedVendorDomain) — bypasses cold-start
    # entirely: a vendor an admin explicitly added is ESTABLISHED even with zero prior Case
    # history for it.
    trusted_vendor_domains: frozenset[str] = field(default_factory=frozenset)


def empty_sender_history() -> SenderHistorySnapshot:
    """No prior history and no trusted-vendor list — the cold-start starting point (a
    brand-new account, or any caller with no account context)."""
    return SenderHistorySnapshot()


def build_sender_history(
    case_rows: list[tuple[str | None, datetime]],
    trusted_vendor_domains: frozenset[str] = frozenset(),
) -> SenderHistorySnapshot:
    """Pure function: folds a flat list of (from_addr, created_at) pairs — one per past
    Case, already scoped to one account and to the lookback window by the caller — into a
    per-domain snapshot. Never called with a row for the email currently being analyzed
    (that Case doesn't exist yet at the point the loader runs), so a poisoning attempt can
    never make its own email count as its own prior history."""
    domains: dict[str, DomainHistory] = {}
    for from_addr, created_at in case_rows:
        if not from_addr or "@" not in from_addr:
            continue
        domain = registrable_domain(from_addr.rsplit("@", 1)[-1].lower())
        existing = domains.get(domain)
        if existing is None:
            domains[domain] = DomainHistory(
                domain=domain, seen_count=1, first_seen=created_at, last_seen=created_at
            )
        else:
            domains[domain] = DomainHistory(
                domain=domain,
                seen_count=existing.seen_count + 1,
                first_seen=min(existing.first_seen, created_at),
                last_seen=max(existing.last_seen, created_at),
            )
    return SenderHistorySnapshot(domains=domains, trusted_vendor_domains=trusted_vendor_domains)


def classify_sender(snapshot: SenderHistorySnapshot, domain: str) -> SenderClassification:
    if domain in snapshot.trusted_vendor_domains:
        return SenderClassification.ESTABLISHED

    history = snapshot.domains.get(domain)
    if history is None:
        return SenderClassification.FIRST_CONTACT

    # A "regular correspondent" bar, not just "seen once" — one prior email (possibly the
    # attacker's own reconnaissance message, or a same-burst duplicate) must never be enough
    # to seed the baseline a later look-alike domain gets compared against. Requires both a
    # minimum occurrence count AND a minimum real time-span, so N emails sent in one minute
    # don't count as "regular" either.
    span_days = (history.last_seen - history.first_seen).total_seconds() / 86400
    if (
        history.seen_count >= settings.sender_history_established_min_occurrences
        and span_days >= settings.sender_history_established_min_span_days
    ):
        return SenderClassification.ESTABLISHED
    return SenderClassification.SEEN_BEFORE


def established_domains(snapshot: SenderHistorySnapshot) -> set[str]:
    """The comparison basis for look-alike-of-known-sender checks — every domain this
    account regularly corresponds with, plus the explicit trusted-vendor allowlist."""
    regular = {
        d for d in snapshot.domains
        if classify_sender(snapshot, d) == SenderClassification.ESTABLISHED
    }
    return regular | set(snapshot.trusted_vendor_domains)
