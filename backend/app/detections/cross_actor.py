"""Cross-actor correlation (Stage 1 detection hardening) — two pure functions that see
across MULTIPLE actors at once, which app.detections.base.ActorEventWindow structurally
cannot represent (it's scoped to one actor). Not registered in app.detections.engine's
_RULES: that registry assumes one shared single-actor window; app.api.routes.events calls
these directly with account-wide/batch-wide data instead. Neither touches the DB."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from app.detections.base import make_finding
from app.events.schema import ActivityEvent
from app.core.config import settings
from app.models.schemas import Finding, Severity


def _subnet_key(source_ip: str | None) -> str | None:
    """First three dot-separated octets of an IPv4-shaped address (e.g. "203.0.113.11" ->
    "203.0.113") — plain string splitting, no ipaddress-module dependency. A single exact
    IP (brute_force's existing per-actor check) is too narrow to catch a campaign that
    rotates through a handful of addresses in the same /24. Anything not exactly 4 numeric
    dot-separated segments (IPv6, malformed, missing) is returned unchanged, so it can only
    ever exact-match itself — never silently over-groups unrelated non-IPv4 values."""
    if not source_ip:
        return None
    parts = source_ip.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return ".".join(parts[:3])
    return source_ip


@dataclass(frozen=True)
class CrossActorFinding:
    """One correlated finding spanning multiple actors — a plain Finding has no notion of
    "which actors," only evidence_event_ids."""

    actors: list[str]
    finding: Finding
    window_start: datetime
    window_end: datetime


@dataclass(frozen=True)
class ActorOutcome:
    """One actor's already-computed standard-window result for the current ingestion
    batch, built by app.api.routes.events from the existing per-actor engine run, BEFORE
    any incident is persisted. `suspicious_source_ips` is deliberately narrow: only the
    source_ip values attached to events actually cited as evidence by this actor's own
    findings — not every IP seen in their window. This keeps two unrelated actors who
    happen to share a corporate VPN egress IP (each separately tripping an unrelated
    detector) from being merged just because of incidental, non-suspicious shared traffic."""

    actor: str
    verdict_is_safe: bool
    findings: list[Finding]
    suspicious_source_ips: list[str]
    window_start: datetime
    window_end: datetime


def detect_password_spray(auth_fail_events: list[ActivityEvent]) -> list[CrossActorFinding]:
    """`auth_fail_events` is every auth_fail event for the account within the caller's
    chosen lookback window, spanning every actor, not just the current batch's. Groups by
    source-IP /24 subnet, then finds (per subnet) the largest sliding sub-window
    (cross_actor_spray_window_minutes) by DISTINCT ACTOR count — mirrors
    brute_force._max_auth_fail_burst's two-pointer scan, but the quantity being maximized
    is distinct actors, not raw event count."""
    by_subnet: dict[str, list[ActivityEvent]] = {}
    for e in auth_fail_events:
        key = _subnet_key(e.source_ip)
        if key is None:
            continue
        by_subnet.setdefault(key, []).append(e)

    window = timedelta(minutes=settings.cross_actor_spray_window_minutes)
    results: list[CrossActorFinding] = []

    for subnet, events in by_subnet.items():
        events = sorted(events, key=lambda e: e.timestamp)
        best_actors: set[str] = set()
        best_window: list[ActivityEvent] = []
        left = 0
        for right in range(len(events)):
            while events[right].timestamp - events[left].timestamp > window:
                left += 1
            span = events[left : right + 1]
            actors = {e.actor for e in span}
            if len(actors) > len(best_actors):
                best_actors, best_window = actors, span

        if len(best_actors) < settings.cross_actor_spray_min_actors:
            continue

        actors_sorted = sorted(best_actors)
        results.append(
            CrossActorFinding(
                actors=actors_sorted,
                finding=make_finding(
                    id="CROSS_ACTOR_PASSWORD_SPRAY",
                    category="access",
                    title="Cross-actor password spray",
                    description=(
                        f"{len(best_window)} failed authentication attempts across "
                        f"{len(actors_sorted)} distinct accounts from source IPs in "
                        f"{subnet}.0/24 within a "
                        f"{settings.cross_actor_spray_window_minutes}-minute window — no "
                        f"single account crossed the per-actor brute-force floor, but the "
                        f"same source correlated across many accounts did."
                    ),
                    severity=Severity.HIGH,
                    points=min(
                        70.0,
                        30.0 + 2.0 * (len(actors_sorted) - settings.cross_actor_spray_min_actors),
                    ),
                    evidence_event_ids=[e.id for e in best_window if e.id is not None],
                ),
                window_start=best_window[0].timestamp,
                window_end=best_window[-1].timestamp,
            )
        )
    return results


def detect_coordinated_campaign(outcomes: list[ActorOutcome]) -> list[CrossActorFinding]:
    """Batch-scoped only (Stage 1 boundary — cross-batch/cross-request correlation would
    need a materially different design, e.g. a background reconciliation job). Groups
    already-non-safe actors into connected components by shared source-IP /24 subnet
    (drawn only from each actor's own suspicious evidence IPs), then keeps components with
    at least coordinated_attack_min_actors members."""
    candidates = [o for o in outcomes if not o.verdict_is_safe]
    subnet_sets = {
        o.actor: {key for ip in o.suspicious_source_ips if (key := _subnet_key(ip)) is not None}
        for o in candidates
    }

    parent = {o.actor: o.actor for o in candidates}

    def find(a: str) -> str:
        while parent[a] != a:
            parent[a] = parent[parent[a]]
            a = parent[a]
        return a

    def union(a: str, b: str) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb

    for i, a in enumerate(candidates):
        for b in candidates[i + 1 :]:
            if subnet_sets[a.actor] & subnet_sets[b.actor]:
                union(a.actor, b.actor)

    groups: dict[str, list[ActorOutcome]] = {}
    for o in candidates:
        groups.setdefault(find(o.actor), []).append(o)

    results: list[CrossActorFinding] = []
    for members in groups.values():
        if len(members) < settings.coordinated_attack_min_actors:
            continue
        actors_sorted = sorted(m.actor for m in members)
        results.append(
            CrossActorFinding(
                actors=actors_sorted,
                finding=make_finding(
                    id="COORDINATED_ATTACK_CORRELATION",
                    category="correlation",
                    title="Coordinated attack across multiple accounts",
                    description=(
                        f"{len(actors_sorted)} accounts were independently flagged as "
                        f"non-safe in the same ingestion batch, correlated via a shared "
                        f"source-IP subnet on their own triggering evidence — consistent "
                        f"with a single coordinated campaign rather than "
                        f"{len(actors_sorted)} unrelated compromises."
                    ),
                    severity=Severity.HIGH,
                    points=25.0,
                    evidence_event_ids=[
                        eid for m in members for f in m.findings for eid in f.evidence_event_ids
                    ],
                ),
                window_start=min(m.window_start for m in members),
                window_end=max(m.window_end for m in members),
            )
        )
    return results
