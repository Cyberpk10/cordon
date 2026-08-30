from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.indicators import sender_history
from app.channels.message import Channel
from app.models.schemas import Severity
from app.parsing.eml_parser import ParsedEmail
from app.sender_history.aggregation import DomainHistory, SenderHistorySnapshot

_NOW = datetime(2026, 6, 1, tzinfo=timezone.utc)


def _established(domain: str, count: int = 5, days_ago: int = 30) -> SenderHistorySnapshot:
    return SenderHistorySnapshot(
        domains={domain: DomainHistory(domain, count, _NOW - timedelta(days=days_ago), _NOW)}
    )


def test_first_contact_sender_fires_for_unseen_domain():
    email = ParsedEmail(from_address="notifications@brand-new-vendor.example")
    ids = {i.id for i in sender_history.evaluate(email, SenderHistorySnapshot())}
    assert "FIRST_CONTACT_SENDER" in ids


def test_no_first_contact_flag_for_established_sender():
    email = ParsedEmail(from_address="billing@acme-vendor.example")
    result = sender_history.evaluate(email, _established("acme-vendor.example"))
    assert result == []


def test_unknown_vendor_claim_fires_with_relationship_language_and_no_history():
    email = ParsedEmail(
        from_address="notifications@meridian-compliance-portal.example",
        subject="Your Q3 vendor access review is ready",
        body_text="Meridian handles the quarterly vendor access reviews for our partners.",
    )
    ids = {i.id for i in sender_history.evaluate(email, SenderHistorySnapshot())}
    assert {"FIRST_CONTACT_SENDER", "UNKNOWN_VENDOR_CLAIM"} <= ids


def test_benign_first_contact_email_raises_only_modest_risk():
    """A new customer's first inquiry — first contact, but no vendor-relationship claim —
    must not trigger UNKNOWN_VENDOR_CLAIM, and FIRST_CONTACT_SENDER alone must stay
    low-score (well under the Suspicious band)."""
    email = ParsedEmail(
        from_address="jane@newcustomer.example",
        subject="Question about your pricing",
        body_text="Hi, I found your product online and wanted to ask about pricing tiers.",
    )
    indicators = sender_history.evaluate(email, SenderHistorySnapshot())
    ids = {i.id for i in indicators}
    assert ids == {"FIRST_CONTACT_SENDER"}
    assert sum(i.score for i in indicators) < 24  # well under SAFE_MAX


def test_lookalike_of_known_sender_flags_high():
    email = ParsedEmail(from_address="billing@acme-vend0r.example")  # 0-for-o typo
    indicators = sender_history.evaluate(email, _established("acme-vendor.example"))
    ids = {i.id for i in indicators}
    assert "LOOKALIKE_OF_KNOWN_SENDER" in ids
    lookalike = next(i for i in indicators if i.id == "LOOKALIKE_OF_KNOWN_SENDER")
    assert lookalike.severity == Severity.HIGH


def test_established_sender_with_vendor_claim_language_stays_clean():
    email = ParsedEmail(
        from_address="billing@acme-vendor.example",
        subject="Invoice #4471",
        body_text="As discussed, please find your invoice attached.",
    )
    # Vendor-claim language + an ESTABLISHED sender must not fire UNKNOWN_VENDOR_CLAIM —
    # that check is gated on FIRST_CONTACT only.
    assert sender_history.evaluate(email, _established("acme-vendor.example")) == []


def test_single_prior_email_does_not_yet_count_as_established_for_lookalike_baseline():
    snapshot = SenderHistorySnapshot(
        domains={"acme-vendor.example": DomainHistory("acme-vendor.example", 1, _NOW, _NOW)}
    )
    email = ParsedEmail(from_address="billing@acme-vend0r.example")
    ids = {i.id for i in sender_history.evaluate(email, snapshot)}
    assert "LOOKALIKE_OF_KNOWN_SENDER" not in ids


def test_trusted_vendor_domain_suppresses_first_contact():
    snapshot = SenderHistorySnapshot(trusted_vendor_domains=frozenset({"newpartner.example"}))
    email = ParsedEmail(from_address="hello@newpartner.example")
    assert sender_history.evaluate(email, snapshot) == []


def test_chat_channel_self_skips():
    message = ParsedEmail(channel=Channel.SLACK, from_address="x@example.com")
    assert sender_history.evaluate(message, SenderHistorySnapshot()) == []


def test_no_history_context_returns_empty():
    email = ParsedEmail(from_address="anyone@example.com")
    assert sender_history.evaluate(email, None) == []
