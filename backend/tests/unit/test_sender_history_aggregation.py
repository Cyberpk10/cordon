from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.sender_history.aggregation import (
    DomainHistory,
    SenderClassification,
    SenderHistorySnapshot,
    build_sender_history,
    classify_sender,
    established_domains,
)

_NOW = datetime(2026, 6, 1, tzinfo=timezone.utc)


def test_classify_sender_first_contact_for_unseen_domain():
    snapshot = SenderHistorySnapshot()
    assert classify_sender(snapshot, "unseen.example") == SenderClassification.FIRST_CONTACT


def test_classify_sender_seen_before_not_yet_established_single_occurrence():
    snapshot = SenderHistorySnapshot(
        domains={"vendor.example": DomainHistory("vendor.example", 1, _NOW, _NOW)}
    )
    assert classify_sender(snapshot, "vendor.example") == SenderClassification.SEEN_BEFORE


def test_classify_sender_established_after_min_occurrences_and_span():
    snapshot = SenderHistorySnapshot(
        domains={
            "vendor.example": DomainHistory(
                "vendor.example", 5, _NOW - timedelta(days=30), _NOW
            )
        }
    )
    assert classify_sender(snapshot, "vendor.example") == SenderClassification.ESTABLISHED


def test_classify_sender_single_burst_of_occurrences_stays_seen_before():
    """Adversarial guard: 5 occurrences all within the same hour (span < 1 day) must not
    count as ESTABLISHED — a single reconnaissance burst shouldn't seed a trusted baseline
    for a later look-alike attack against itself."""
    snapshot = SenderHistorySnapshot(
        domains={
            "vendor.example": DomainHistory(
                "vendor.example", 5, _NOW, _NOW + timedelta(minutes=30)
            )
        }
    )
    assert classify_sender(snapshot, "vendor.example") == SenderClassification.SEEN_BEFORE


def test_trusted_vendor_domain_is_established_with_zero_case_history():
    snapshot = SenderHistorySnapshot(trusted_vendor_domains=frozenset({"newpartner.example"}))
    assert classify_sender(snapshot, "newpartner.example") == SenderClassification.ESTABLISHED


def test_established_domains_excludes_seen_before_and_first_contact():
    snapshot = SenderHistorySnapshot(
        domains={
            "established.example": DomainHistory(
                "established.example", 5, _NOW - timedelta(days=30), _NOW
            ),
            "seen-once.example": DomainHistory("seen-once.example", 1, _NOW, _NOW),
        },
        trusted_vendor_domains=frozenset({"trusted.example"}),
    )
    assert established_domains(snapshot) == {"established.example", "trusted.example"}


def test_build_sender_history_aggregates_by_registrable_domain():
    rows = [
        ("billing@sub.vendor.example", _NOW - timedelta(days=10)),
        ("support@sub.vendor.example", _NOW - timedelta(days=5)),
        ("hello@other.example", _NOW),
        (None, _NOW),
    ]
    snapshot = build_sender_history(rows)
    assert snapshot.domains["vendor.example"].seen_count == 2
    assert snapshot.domains["other.example"].seen_count == 1
    assert "vendor.example" in snapshot.domains
