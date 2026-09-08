"""Cross-references link destinations against the multi-feed threat-intel snapshot
(threat-intelligence enrichment Stage 1 — see app.threat_intel.loader and
app/threat_intel/data/sources.md for feed provenance/licenses). Generalizes what used to be
a PhishTank-only hostname check (LINK_KNOWN_PHISHING_HOST, M8 Stage 3a) into a multi-feed
hostname-OR-full-URL match.

STALENESS LIMITATION (same spirit as lookalike_domain.py's curated-brand-list limitation):
this is a point-in-time snapshot, not a live feed. A match is strong corroborating evidence
when it hits; the miss rate against infrastructure that appeared after the snapshot date
grows every day past it. Refresh via scripts/refresh_threat_intel.py.

Purely offline: matched against a static bundled snapshot, no network calls.
"""

from __future__ import annotations

from app.core.config import settings
from app.indicators.base import make_indicator
from app.channels.message import Message
from app.models.schemas import Indicator, Severity
from app.sender_history.aggregation import SenderHistorySnapshot
from app.threat_intel.loader import match_hostname, match_url


def evaluate(
    email: Message, sender_history: SenderHistorySnapshot | None = None
) -> list[Indicator]:
    if not settings.enable_threat_intel_indicators:
        return []

    matched: list[str] = []
    for link in email.links:
        match = match_hostname(link.href_domain) or match_url(link.href)
        if match is not None:
            matched.append(
                f"{link.href_domain or link.href} — feed={match.feed}, "
                f"snapshot={match.snapshot_date} ({link.href})"
            )

    if not matched:
        return []

    return [
        make_indicator(
            id="LINK_KNOWN_MALICIOUS",
            category="link",
            title="Link matches a known-malicious host/URL feed",
            description=(
                "One or more links match a hostname or URL on a bundled threat-intelligence "
                "feed's known-malicious list. This is a static, point-in-time snapshot — a "
                "match is strong corroborating evidence, but this list is not a live feed "
                "and will miss infrastructure that appeared after the snapshot date."
            ),
            evidence=matched,
            severity=Severity.HIGH,
            score=60,
        )
    ]
