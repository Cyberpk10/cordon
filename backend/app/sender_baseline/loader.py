"""The only DB code for sender baselines: load one sender's baseline, record an observation,
and find the account's own domains. Mirrors app.sender_history.loader."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Callable
from uuid import UUID

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.time import to_naive_utc
from app.db.models import SenderObservation, SimulationDomain, User
from app.indicators.domain_utils import registrable_domain
from app.sender_baseline.aggregation import ObservationRow, SenderBaseline, build_baseline
from app.sender_baseline.signals import MessageSignals

# Consumer mailbox providers: a shared provider domain says nothing about which organisation
# a user belongs to, so it never makes another sender a "colleague".
FREE_MAIL_DOMAINS = frozenset({
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "hotmail.co.uk", "live.com",
    "msn.com", "yahoo.com", "yahoo.co.uk", "ymail.com", "icloud.com", "me.com", "mac.com",
    "aol.com", "proton.me", "protonmail.com", "pm.me", "gmx.com", "gmx.net", "mail.com",
    "zoho.com", "yandex.com", "yandex.ru", "qq.com", "163.com", "126.com", "comcast.net",
    "att.net", "verizon.net", "fastmail.com", "hey.com",
})


def _cutoff() -> datetime:
    return datetime.now(timezone.utc) - timedelta(days=settings.sender_history_lookback_days)


def load_sender_baseline(db: Session, account_id: UUID, from_addr: str) -> SenderBaseline:
    addr = from_addr.strip().lower()
    rows = (
        db.query(SenderObservation)
        .filter(
            SenderObservation.account_id == account_id,
            SenderObservation.from_addr == addr,
            SenderObservation.observed_at >= _cutoff(),
        )
        .all()
    )
    return build_baseline(
        addr,
        [
            ObservationRow(
                observed_at=to_naive_utc(r.observed_at),
                message_hour_utc=r.message_hour_utc,
                sending_country=r.sending_country,
                country_source=r.country_source,
                sending_provider=r.sending_provider,
                reply_to_domain=r.reply_to_domain,
                return_path_domain=r.return_path_domain,
                auth_pass=r.auth_pass,
                verdict=r.verdict,
            )
            for r in rows
        ],
    )


def baseline_lookup_for(db: Session, account_id: UUID) -> Callable[[str], SenderBaseline]:
    """The callable run_email_pipeline uses to fetch the sender's baseline once it has parsed
    the From address."""
    return lambda from_addr: load_sender_baseline(db, account_id, from_addr)


def load_account_domains(db: Session, account_id: UUID) -> frozenset[str]:
    """The account's own organisation domains: its users' email domains (minus consumer
    providers) plus simulation domains it has verified by DNS."""
    domains: set[str] = set()
    for (email,) in db.query(User.email).filter(User.account_id == account_id).all():
        if email and "@" in email:
            domains.add(registrable_domain(email.rsplit("@", 1)[-1].lower()))
    for (domain,) in (
        db.query(SimulationDomain.domain)
        .filter(SimulationDomain.account_id == account_id, SimulationDomain.status == "verified")
        .all()
    ):
        domains.add(registrable_domain(domain.lower()))
    return frozenset(domains - FREE_MAIL_DOMAINS)


def record_observation(
    db: Session, account_id: UUID, content_hash: str, signals: MessageSignals | None, verdict: str
) -> None:
    """Adds one observation (no commit; the caller's transaction does). A no-op for chat
    messages, email without a From address, and an email this account already recorded."""
    if signals is None:
        return
    exists = (
        db.query(SenderObservation.id)
        .filter(
            SenderObservation.account_id == account_id,
            SenderObservation.content_hash == content_hash,
        )
        .first()
    )
    if exists is not None:
        return
    row = (
        SenderObservation(
            account_id=account_id,
            from_addr=signals.from_addr,
            from_domain=signals.from_domain,
            content_hash=content_hash,
            message_hour_utc=signals.message_hour_utc,
            sending_ip=signals.sending_ip,
            sending_country=signals.sending_country,
            country_source=signals.country_source,
            sending_provider=signals.sending_provider,
            reply_to_domain=signals.reply_to_domain,
            return_path_domain=signals.return_path_domain,
            auth_pass=signals.auth_pass,
            verdict=verdict,
        )
    )
    try:
        with db.begin_nested():  # a concurrent duplicate loses the unique-key race quietly
            db.add(row)
    except IntegrityError:
        pass


def purge_old_observations(db: Session) -> int:
    """Deletes observations older than the lookback window. Returns how many."""
    deleted = (
        db.query(SenderObservation)
        .filter(SenderObservation.observed_at < _cutoff())
        .delete(synchronize_session=False)
    )
    db.commit()
    return deleted
