from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.detections.cross_actor import (
    ActorOutcome,
    detect_coordinated_campaign,
    detect_password_spray,
)
from app.events.schema import ActivityEvent, EventAction
from app.models.schemas import Finding, Severity

_BASE = datetime(2026, 1, 6, 10, 0, tzinfo=timezone.utc)


def _auth_fail(actor: str, minute_offset: int, source_ip: str) -> ActivityEvent:
    return ActivityEvent(
        timestamp=_BASE + timedelta(minutes=minute_offset),
        actor=actor,
        action=EventAction.AUTH_FAIL,
        source_ip=source_ip,
        outcome="failure",
    )


def _finding(fid: str = "BRUTE_FORCE_PASSWORD_SPRAY") -> Finding:
    return Finding(
        id=fid, category="access", title="t", description="d",
        severity=Severity.HIGH, points=40.0, evidence_event_ids=[],
    )


def _outcome(actor: str, *, safe: bool, ips: list[str]) -> ActorOutcome:
    return ActorOutcome(
        actor=actor,
        verdict_is_safe=safe,
        findings=[] if safe else [_finding()],
        suspicious_source_ips=ips,
        window_start=_BASE,
        window_end=_BASE + timedelta(minutes=30),
    )


# --------------------------------------------------------------------------------------
# detect_password_spray
# --------------------------------------------------------------------------------------


def test_fires_when_many_actors_fail_from_same_subnet_within_window():
    ips = ["203.0.113.5", "203.0.113.9", "203.0.113.20"]
    events = [
        _auth_fail(f"spray-{i:02d}@corp.com", i * 0.5, ips[i % len(ips)]) for i in range(15)
    ]
    findings = detect_password_spray(events)

    assert len(findings) == 1
    assert findings[0].finding.id == "CROSS_ACTOR_PASSWORD_SPRAY"
    assert len(findings[0].actors) == 15


def test_does_not_fire_below_min_actors():
    events = [_auth_fail(f"user-{i}@corp.com", i, "203.0.113.5") for i in range(3)]
    assert detect_password_spray(events) == []


def test_does_not_fire_across_different_subnets():
    events = [_auth_fail(f"user-{i}@corp.com", i, "203.0.113.5") for i in range(4)]
    events += [_auth_fail(f"other-{i}@corp.com", i, "198.51.100.5") for i in range(4)]
    assert detect_password_spray(events) == []


def test_does_not_fire_when_spread_beyond_window():
    events = [_auth_fail(f"user-{i}@corp.com", i * 20, "203.0.113.5") for i in range(8)]
    assert detect_password_spray(events) == []


# --------------------------------------------------------------------------------------
# detect_coordinated_campaign
# --------------------------------------------------------------------------------------


def test_coordinated_campaign_merges_three_non_safe_actors_sharing_subnet():
    outcomes = [
        _outcome("a@corp.com", safe=False, ips=["203.0.113.10"]),
        _outcome("b@corp.com", safe=False, ips=["203.0.113.11"]),
        _outcome("c@corp.com", safe=False, ips=["203.0.113.12"]),
    ]
    groups = detect_coordinated_campaign(outcomes)

    assert len(groups) == 1
    assert groups[0].actors == ["a@corp.com", "b@corp.com", "c@corp.com"]
    assert groups[0].finding.id == "COORDINATED_ATTACK_CORRELATION"


def test_coordinated_campaign_does_not_merge_below_min_actors():
    outcomes = [
        _outcome("a@corp.com", safe=False, ips=["203.0.113.10"]),
        _outcome("b@corp.com", safe=False, ips=["203.0.113.11"]),
    ]
    assert detect_coordinated_campaign(outcomes) == []


def test_coordinated_campaign_ignores_safe_actors_sharing_subnet():
    outcomes = [
        _outcome("a@corp.com", safe=True, ips=["203.0.113.10"]),
        _outcome("b@corp.com", safe=True, ips=["203.0.113.11"]),
        _outcome("c@corp.com", safe=False, ips=["203.0.113.12"]),
    ]
    assert detect_coordinated_campaign(outcomes) == []


# --------------------------------------------------------------------------------------
# Detection max-out Stage D — weak-signal candidacy (relaxed filter).
# --------------------------------------------------------------------------------------


def _weak_signal_outcome(actor: str, *, ips: list[str]) -> ActorOutcome:
    """A SAFE actor (no firing finding at all) who is nonetheless a weak-signal candidate —
    models a coordinated campaign where every participant stays individually sub-threshold."""
    return ActorOutcome(
        actor=actor, verdict_is_safe=True, findings=[], suspicious_source_ips=ips,
        window_start=_BASE, window_end=_BASE + timedelta(minutes=30), weak_signal_candidate=True,
    )


def test_coordinated_campaign_now_groups_sub_threshold_weak_signal_actors_sharing_a_subnet():
    """The real capability Stage D adds: before, three individually-safe actors sharing
    infrastructure produced zero candidates (old filter was verdict_is_safe-only)."""
    outcomes = [
        _weak_signal_outcome("a@corp.com", ips=["203.0.113.10"]),
        _weak_signal_outcome("b@corp.com", ips=["203.0.113.11"]),
        _weak_signal_outcome("c@corp.com", ips=["203.0.113.12"]),
    ]
    groups = detect_coordinated_campaign(outcomes)
    assert len(groups) == 1
    assert groups[0].actors == ["a@corp.com", "b@corp.com", "c@corp.com"]
    assert groups[0].finding.id == "COORDINATED_ATTACK_CORRELATION"


def test_coordinated_campaign_still_ignores_plain_safe_actors_without_weak_signal():
    outcomes = [
        _outcome("a@corp.com", safe=True, ips=["203.0.113.10"]),
        _outcome("b@corp.com", safe=True, ips=["203.0.113.11"]),
        _outcome("c@corp.com", safe=True, ips=["203.0.113.12"]),
    ]
    assert detect_coordinated_campaign(outcomes) == []


def test_coordinated_campaign_honest_limit_does_not_group_unrelated_infrastructure():
    """Phase 4 #6's exact construction: sub-threshold weak-signal actors, but each on a
    genuinely DIFFERENT /24 subnet — candidacy relaxation alone does not close this, since
    grouping still requires shared-subnet evidence. Documented, by-design remaining miss."""
    outcomes = [
        _weak_signal_outcome("a@corp.com", ips=["203.0.113.10"]),
        _weak_signal_outcome("b@corp.com", ips=["198.51.100.11"]),
        _weak_signal_outcome("c@corp.com", ips=["91.198.174.12"]),
    ]
    assert detect_coordinated_campaign(outcomes) == []


def test_coordinated_campaign_ignores_incidental_ip_not_in_evidence():
    # All non-safe, but each actor's own suspicious evidence points at an unrelated
    # subnet — models "shares a benign IP incidentally, but that IP was never cited as
    # evidence" (the route only ever passes evidence-derived IPs into suspicious_source_ips
    # in the first place; this pins that disjoint evidence never gets merged).
    outcomes = [
        _outcome("a@corp.com", safe=False, ips=["203.0.113.10"]),
        _outcome("b@corp.com", safe=False, ips=["198.51.100.11"]),
        _outcome("c@corp.com", safe=False, ips=["91.198.174.12"]),
    ]
    assert detect_coordinated_campaign(outcomes) == []
