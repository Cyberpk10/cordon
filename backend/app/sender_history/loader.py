"""Thin DB-query loader — the only place app.sender_history touches SQLAlchemy. Mirrors
app.api.routes.events._load_baseline_snapshot's separation: this function queries, the pure
aggregation module (app.sender_history.aggregation) computes."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID

from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models import Case, TrustedVendorDomain
from app.sender_history.aggregation import SenderHistorySnapshot, build_sender_history


def load_sender_history(db: Session, account_id: UUID) -> SenderHistorySnapshot:
    cutoff = datetime.now(timezone.utc) - timedelta(days=settings.sender_history_lookback_days)
    rows = (
        db.query(Case.from_addr, Case.created_at)
        .filter(
            Case.account_id == account_id,
            Case.channel == "email",
            Case.from_addr.is_not(None),
            Case.created_at >= cutoff,
        )
        .all()
    )
    trusted = frozenset(
        row[0]
        for row in db.query(TrustedVendorDomain.domain)
        .filter(TrustedVendorDomain.account_id == account_id)
        .all()
    )
    return build_sender_history(list(rows), trusted)
