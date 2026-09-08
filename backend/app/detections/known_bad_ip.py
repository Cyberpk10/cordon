"""Cross-references each event's source_ip against the multi-feed threat-intel snapshot
(threat-intelligence enrichment Stage 1 — see app.threat_intel.loader and
app/threat_intel/data/sources.md for feed provenance/licenses) — the events-side counterpart
to app.indicators.known_bad_urls/known_bad_sender's email-side checks.

Doesn't use behavioral baselines — a source IP matching a known-malicious/anonymizing feed
is suspicious regardless of the actor's history, same rationale as data_exfiltration.py.
Purely offline: matched against a static bundled snapshot, no network calls.
"""

from __future__ import annotations

from app.baselines.aggregation import BaselineSnapshot
from app.core.config import settings
from app.detections.base import ActorEventWindow, make_finding
from app.models.schemas import Finding, Severity
from app.threat_intel.loader import match_ip


def evaluate(window: ActorEventWindow, baseline: BaselineSnapshot | None = None) -> list[Finding]:
    if not settings.enable_threat_intel_indicators:
        return []

    matched: list[str] = []
    matched_event_ids = []
    seen_feeds: set[str] = set()
    for event in window.events:
        match = match_ip(event.source_ip)
        if match is None:
            continue
        seen_feeds.add(match.feed)
        matched.append(f"{event.source_ip} — feed={match.feed}, snapshot={match.snapshot_date}")
        if event.id is not None:
            matched_event_ids.append(event.id)

    if not matched:
        return []

    return [
        make_finding(
            id="EVENT_IP_KNOWN_MALICIOUS",
            category="threat_intel",
            title="Event source IP matches a known-malicious/anonymizing feed",
            description=(
                f"'{window.actor}' had activity from an IP matching feed(s) "
                f"{', '.join(sorted(seen_feeds))} — not a broad claim of known C2 "
                "infrastructure unless that is specifically what matched; check the feed "
                "name(s) for what actually matched. Static, point-in-time snapshot."
            ),
            severity=Severity.HIGH,
            points=60,
            evidence_event_ids=matched_event_ids,
        )
    ]
