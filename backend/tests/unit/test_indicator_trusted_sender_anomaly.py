from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.indicators import trusted_sender_anomaly
from app.models.schemas import Severity
from app.parsing.eml_parser import Link, ParsedEmail
from app.channels.message import Channel
from app.sender_history.aggregation import DomainHistory, SenderHistorySnapshot

_NOW = datetime(2026, 6, 1, tzinfo=timezone.utc)


def _established(domain: str = "acme-vendor.example", count: int = 5, days_ago: int = 30) -> SenderHistorySnapshot:
    return SenderHistorySnapshot(
        domains={domain: DomainHistory(domain, count, _NOW - timedelta(days=days_ago), _NOW - timedelta(days=1))}
    )


def _seen_once(domain: str = "acme-vendor.example") -> SenderHistorySnapshot:
    return SenderHistorySnapshot(domains={domain: DomainHistory(domain, 1, _NOW, _NOW)})


def test_established_vendor_bank_change_with_urgency_and_offpattern_link_flags():
    email = ParsedEmail(
        from_address="billing@acme-vendor.example",
        subject="Urgent: updated payment details",
        body_text="Please note we have a change of bank details - act now to avoid payment delays.",
        links=[Link(display_text="update now", href="https://acme-payment-update.info/x", href_domain="acme-payment-update.info")],
    )
    indicators = trusted_sender_anomaly.evaluate(email, _established())
    ids = {i.id for i in indicators}
    assert "TRUSTED_SENDER_ANOMALY" in ids
    finding = next(i for i in indicators if i.id == "TRUSTED_SENDER_ANOMALY")
    assert finding.severity == Severity.HIGH


def test_same_vendor_routine_invoice_stays_safe():
    email = ParsedEmail(
        from_address="billing@acme-vendor.example",
        subject="Invoice #123",
        body_text="Please find attached invoice for services rendered this month, payable within 30 days.",
        links=[Link(display_text="view invoice", href="https://acme-vendor.example/invoice/123", href_domain="acme-vendor.example")],
    )
    assert trusted_sender_anomaly.evaluate(email, _established()) == []


def test_single_prior_email_does_not_exempt_sender_from_content_scrutiny():
    """The exact Phase 4 gap this stage closes: a sender seen only ONCE before (SEEN_BEFORE,
    not the fuller ESTABLISHED bar) must still be scrutinized, not just fully-trusted senders."""
    email = ParsedEmail(
        from_address="billing@acme-vendor.example",
        subject="Urgent: updated payment details",
        body_text="Please note we have a change of bank details - act now to avoid payment delays.",
        links=[Link(display_text="update now", href="https://acme-payment-update.info/x", href_domain="acme-payment-update.info")],
    )
    indicators = trusted_sender_anomaly.evaluate(email, _seen_once())
    assert "TRUSTED_SENDER_ANOMALY" in {i.id for i in indicators}


def test_first_contact_sender_is_not_scrutinized_by_this_indicator():
    """First-contact scrutiny is FIRST_CONTACT_SENDER/UNKNOWN_VENDOR_CLAIM's job, not this one."""
    email = ParsedEmail(
        from_address="billing@acme-vendor.example",
        subject="Urgent: updated payment details",
        body_text="Please note we have a change of bank details - act now to avoid payment delays.",
        links=[Link(display_text="update now", href="https://acme-payment-update.info/x", href_domain="acme-payment-update.info")],
    )
    assert trusted_sender_anomaly.evaluate(email, SenderHistorySnapshot()) == []


def test_legitimate_password_reset_with_same_domain_link_and_timeboxed_language_stays_safe():
    """A credential ask (verify your account) needs a link-domain anomaly to fire — urgency
    alone is not valid corroboration for credential asks, since legitimate transactional
    security email routinely includes time-boxed wording like 'expires in 24 hours'."""
    email = ParsedEmail(
        from_address="security@acme-vendor.example",
        subject="Password reset requested",
        body_text="Click here to verify your account and reset your password. This link expires in 24 hours.",
        links=[Link(display_text="reset password", href="https://acme-vendor.example/reset", href_domain="acme-vendor.example")],
    )
    assert trusted_sender_anomaly.evaluate(email, _established()) == []


def test_offpattern_link_alone_without_high_risk_ask_stays_safe():
    email = ParsedEmail(
        from_address="billing@acme-vendor.example",
        subject="Check out our blog",
        body_text="We published a new blog post you might enjoy.",
        links=[Link(display_text="read more", href="https://acme-vendor-blog.example/post", href_domain="acme-vendor-blog.example")],
    )
    assert trusted_sender_anomaly.evaluate(email, _established()) == []


def test_payment_change_with_urgency_and_same_domain_link_still_flags():
    """Urgency alone IS valid corroboration for a payment/bank-detail-change ask — a real
    vendor essentially never pairs 'act now' with 'here's our new bank account'."""
    email = ParsedEmail(
        from_address="billing@acme-vendor.example",
        subject="Urgent update",
        body_text="Act now: we have a new bank account for future payments.",
        links=[Link(display_text="details", href="https://acme-vendor.example/update", href_domain="acme-vendor.example")],
    )
    indicators = trusted_sender_anomaly.evaluate(email, _established())
    assert "TRUSTED_SENDER_ANOMALY" in {i.id for i in indicators}


def test_credential_ask_with_randomly_generated_link_domain_flags():
    email = ParsedEmail(
        from_address="billing@acme-vendor.example",
        subject="Account verification needed",
        body_text="Please verify your account by clicking the link below.",
        links=[Link(display_text="verify", href="https://xk29fq7z3m1p.info/verify", href_domain="xk29fq7z3m1p.info")],
    )
    indicators = trusted_sender_anomaly.evaluate(email, _established())
    assert "TRUSTED_SENDER_ANOMALY" in {i.id for i in indicators}


def test_chat_channel_self_skips():
    message = ParsedEmail(
        channel=Channel.SLACK,
        from_address="billing@acme-vendor.example",
        body_text="Act now: we have a new bank account for future payments.",
    )
    assert trusted_sender_anomaly.evaluate(message, _established()) == []


def test_no_history_context_returns_empty():
    email = ParsedEmail(
        from_address="billing@acme-vendor.example",
        body_text="Act now: we have a new bank account for future payments.",
    )
    assert trusted_sender_anomaly.evaluate(email, None) == []


def test_trusted_vendor_link_domain_is_not_off_pattern():
    email = ParsedEmail(
        from_address="billing@acme-vendor.example",
        subject="Urgent: updated payment details",
        body_text="Please note we have a change of bank details - act now to avoid payment delays.",
        links=[Link(display_text="details", href="https://payment-processor.example/x", href_domain="payment-processor.example")],
    )
    snapshot = SenderHistorySnapshot(
        domains=_established().domains,
        trusted_vendor_domains=frozenset({"payment-processor.example"}),
    )
    # Payment-change ask still has urgency as valid corroboration even with a trusted link.
    indicators = trusted_sender_anomaly.evaluate(email, snapshot)
    assert "TRUSTED_SENDER_ANOMALY" in {i.id for i in indicators}
    finding = next(i for i in indicators if i.id == "TRUSTED_SENDER_ANOMALY")
    link_evidence = [e for e in finding.evidence if "unfamiliar domain" in e or "randomly-generated" in e]
    assert not any("payment-processor.example" in e for e in link_evidence)
