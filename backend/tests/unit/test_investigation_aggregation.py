from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from app.investigation.aggregation import (
    RelatedCaseRef,
    TimelineEntry,
    build_scope,
    build_timeline,
    extract_threat_intel_hits,
)


def _ts(day: int) -> datetime:
    return datetime(2026, 1, day, tzinfo=timezone.utc)


def _entry(day: int, source_id: str | None = None) -> TimelineEntry:
    return TimelineEntry(
        timestamp=_ts(day),
        type="login",
        description=f"event on day {day}",
        source="event",
        source_id=source_id or str(day),
    )


def test_build_timeline_sorts_oldest_first():
    entries = [_entry(5), _entry(1), _entry(3)]
    result = build_timeline(entries, max_entries=10)
    assert [e.source_id for e in result] == ["1", "3", "5"]


def test_build_timeline_caps_to_most_recent_entries():
    entries = [_entry(day) for day in range(1, 11)]  # days 1..10
    result = build_timeline(entries, max_entries=3)
    assert [e.source_id for e in result] == ["8", "9", "10"]


def test_build_timeline_empty_input_is_empty_output():
    assert build_timeline([], max_entries=5) == []


# --- extract_threat_intel_hits -----------------------------------------------------------


def test_extract_threat_intel_hits_picks_only_known_threat_intel_indicator_ids():
    indicators = [
        {"id": "SENDER_DOMAIN_KNOWN_BAD", "title": "Known-bad sender domain", "evidence": ["x"]},
        {"id": "LOOKALIKE_DOMAIN", "title": "Lookalike domain", "evidence": ["y"]},  # NOT threat-intel
        {"id": "LINK_KNOWN_MALICIOUS", "title": "Known-bad link", "evidence": ["z"]},
    ]
    hits = extract_threat_intel_hits(indicators, [])
    ids = {h["id"] for h in hits}
    assert ids == {"SENDER_DOMAIN_KNOWN_BAD", "LINK_KNOWN_MALICIOUS"}
    assert all(h["source"] == "email_indicator" for h in hits)


def test_extract_threat_intel_hits_picks_known_bad_ip_findings():
    findings = [
        {"id": "EVENT_IP_KNOWN_MALICIOUS", "title": "Known-bad source IP", "actor": "alice@co.example"},
        {"id": "MASS_FILE_ACCESS", "title": "Mass file access", "actor": "alice@co.example"},
    ]
    hits = extract_threat_intel_hits([], findings)
    assert len(hits) == 1
    assert hits[0]["id"] == "EVENT_IP_KNOWN_MALICIOUS"
    assert hits[0]["source"] == "activity_finding"


def test_extract_threat_intel_hits_empty_when_nothing_matches():
    assert extract_threat_intel_hits([{"id": "URGENCY_LANGUAGE"}], [{"id": "OFF_HOURS_ACCESS"}]) == []


# --- build_scope ----------------------------------------------------------------------


def _related_case(subject: str, to_addresses: list[str]) -> RelatedCaseRef:
    return RelatedCaseRef(
        id=uuid4(),
        created_at=_ts(2),
        verdict="malicious",
        score=90,
        subject=subject,
        to_addresses=to_addresses,
    )


def test_build_scope_finds_other_recipients_targeted_by_the_same_sender():
    related = [_related_case("Urgent: verify", ["bob@co.example"])]
    scope = build_scope(
        targeted_recipients=["alice@co.example"],
        related_cases=related,
        subject="Urgent: verify",
        related_incident_count=0,
        threat_level_band=None,
        ueba_finding_count=0,
    )
    assert scope["other_recipients_same_sender"] == ["bob@co.example"]
    assert scope["possible_additional_targets"] is True
    assert len(scope["likely_same_campaign_case_ids"]) == 1


def test_build_scope_no_additional_targets_when_only_self_targeted():
    scope = build_scope(
        targeted_recipients=["alice@co.example"],
        related_cases=[],
        subject="Hi",
        related_incident_count=0,
        threat_level_band=None,
        ueba_finding_count=0,
    )
    assert scope["other_recipients_same_sender"] == []
    assert scope["possible_additional_targets"] is False
    assert scope["possible_account_compromise"] is False
    assert scope["compromise_signals"] == []


def test_build_scope_flags_possible_compromise_from_related_incidents():
    scope = build_scope(
        targeted_recipients=["alice@co.example"],
        related_cases=[],
        subject=None,
        related_incident_count=2,
        threat_level_band="normal",
        ueba_finding_count=0,
    )
    assert scope["possible_account_compromise"] is True
    assert "2 correlated activity incident(s)" in scope["compromise_signals"][0]


def test_build_scope_flags_possible_compromise_from_elevated_threat_level():
    scope = build_scope(
        targeted_recipients=["alice@co.example"],
        related_cases=[],
        subject=None,
        related_incident_count=0,
        threat_level_band="attack_forming",
        ueba_finding_count=0,
    )
    assert scope["possible_account_compromise"] is True
    assert any("attack_forming" in s for s in scope["compromise_signals"])


def test_build_scope_normal_threat_level_band_is_not_a_compromise_signal():
    scope = build_scope(
        targeted_recipients=["alice@co.example"],
        related_cases=[],
        subject=None,
        related_incident_count=0,
        threat_level_band="normal",
        ueba_finding_count=0,
    )
    assert scope["possible_account_compromise"] is False
