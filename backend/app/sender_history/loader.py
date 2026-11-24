"""Thin DB-query loader — the only place app.sender_history touches SQLAlchemy. Mirrors
app.api.routes.events._load_baseline_snapshot's separation: this function queries, the pure
aggregation module (app.sender_history.aggregation) computes.

History is every distinct email the account has analyzed in the window: saved Cases plus
the metadata-only SenderObservation rows (app.sender_baseline), which also cover clean mail
the add-ons analyze under persist="if_not_clean" without saving a Case. Without the
observations, a sender the account hears from every week through the Gmail add-on would
still read as "first contact" here while the account-takeover baseline calls it a known
sender. Each email counts once: an observation whose content hash matches a Case is skipped.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from uuid import UUID

from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models import Case, SenderObservation, TrustedVendorDomain
from app.sender_baseline.loader import load_account_domains
from app.sender_history.aggregation import SenderHistorySnapshot, build_sender_history


def history_rows(
    db: Session,
    account_id: UUID,
    cutoff: datetime,
    exclude_case: Case | None = None,
) -> list[tuple[str | None, datetime]]:
    """(from_addr, seen_at) per distinct analyzed email since `cutoff`. `exclude_case`
    drops that Case and its own observation, for callers that run after it was saved."""
    case_q = db.query(Case.from_addr, Case.created_at, Case.content_hash).filter(
        Case.account_id == account_id,
        Case.channel == "email",
        Case.from_addr.is_not(None),
        Case.created_at >= cutoff,
    )
    if exclude_case is not None:
        case_q = case_q.filter(Case.id != exclude_case.id)
    cases = case_q.all()

    excluded_hashes = {h for _, _, h in cases if h}
    if exclude_case is not None and exclude_case.content_hash:
        excluded_hashes.add(exclude_case.content_hash)
    observations = (
        db.query(SenderObservation.from_addr, SenderObservation.observed_at, SenderObservation.content_hash)
        .filter(SenderObservation.account_id == account_id, SenderObservation.observed_at >= cutoff)
        .all()
    )
    return [(addr, at) for addr, at, _ in cases] + [
        (addr, at) for addr, at, h in observations if h not in excluded_hashes
    ]


def trusted_vendor_domains(db: Session, account_id: UUID) -> frozenset[str]:
    return frozenset(
        row[0]
        for row in db.query(TrustedVendorDomain.domain)
        .filter(TrustedVendorDomain.account_id == account_id)
        .all()
    )


def load_sender_history(db: Session, account_id: UUID) -> SenderHistorySnapshot:
    cutoff = datetime.now(timezone.utc) - timedelta(days=settings.sender_history_lookback_days)
    snapshot = build_sender_history(
        history_rows(db, account_id, cutoff), trusted_vendor_domains(db, account_id)
    )
    return replace(
        snapshot,
        account_domains=load_account_domains(db, account_id),
        account_lists=load_account_lists(db, account_id),
    )


def load_account_lists(db: Session, account_id: UUID) -> frozenset[tuple[str, str, str]]:
    """Active in-Cordon watch/blocklist entries (D5) as (list_name, kind, value)."""
    from app.db.models import CordonListEntry

    rows = (
        db.query(CordonListEntry.list_name, CordonListEntry.kind, CordonListEntry.value)
        .filter(CordonListEntry.account_id == account_id, CordonListEntry.active.is_(True))
        .all()
    )
    return frozenset((r[0], r[1], r[2]) for r in rows)
