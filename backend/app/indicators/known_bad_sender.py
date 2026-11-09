"""Cross-references the sender's domain and (when derivable) sending IP against the
multi-feed threat-intel snapshot (app.threat_intel.loader) — the sender-side counterpart to
known_bad_urls.py's link check (threat-intelligence enrichment Stage 1).

SENDER_IP_KNOWN_MALICIOUS coverage limitation, documented deliberately: Aegis never performs
its own SPF/DKIM/DMARC verification (see app.parsing.auth_results), so the only sending IP
this SCORED check uses is whatever the RECEIVING mail server's own SPF check already annotated
in the Authentication-Results header (`client-ip=...`). This is real for most
major-provider-relayed mail, absent for direct-SMTP/synthetic messages — a documented coverage
gap, not a bug. Using `Received:` header chains for scoring was considered and rejected: those
are partly spoofable and format varies wildly across providers, a worse false-confidence trade
than a known gap. (Since the source-IP feature, app.parsing.received_chain does parse the
chain, but strictly for DISPLAY with a "lower confidence" label. It never feeds this
indicator or the score.)
"""

from __future__ import annotations

from app.core.config import settings
from app.indicators.base import make_indicator
from app.channels.message import Message
from app.models.schemas import Indicator, Severity
from app.parsing.auth_results import extract_spf_client_ip
from app.sender_history.aggregation import SenderHistorySnapshot
from app.threat_intel.loader import match_hostname, match_ip


def _sender_domain(address: str | None) -> str | None:
    if not address or "@" not in address:
        return None
    return address.rsplit("@", 1)[-1].lower()


def evaluate(
    email: Message, sender_history: SenderHistorySnapshot | None = None
) -> list[Indicator]:
    if not settings.enable_threat_intel_indicators:
        return []

    indicators: list[Indicator] = []

    domain_match = match_hostname(_sender_domain(email.from_address))
    if domain_match is not None:
        indicators.append(
            make_indicator(
                id="SENDER_DOMAIN_KNOWN_BAD",
                category="sender",
                title="Sender domain matches a known-malicious feed",
                description=(
                    "The sending domain matches a hostname on a bundled threat-intelligence "
                    "feed's known-malicious list. Static, point-in-time snapshot — see "
                    "app/threat_intel/data/sources.md for feed provenance."
                ),
                evidence=[
                    f"{email.from_address} — feed={domain_match.feed}, snapshot={domain_match.snapshot_date}"
                ],
                severity=Severity.HIGH,
                score=60,
            )
        )

    client_ip = extract_spf_client_ip(email.auth_results.raw_header)
    ip_match = match_ip(client_ip)
    if ip_match is not None:
        indicators.append(
            make_indicator(
                id="SENDER_IP_KNOWN_MALICIOUS",
                category="sender",
                title="Sending IP matches a known-malicious/anonymizing feed",
                description=(
                    f"The sending IP (from the receiving server's own SPF client-ip "
                    f"annotation) matches feed '{ip_match.feed}' — not a broad claim of "
                    "known C2 infrastructure unless that is specifically what matched; "
                    "check the feed name for what it actually means."
                ),
                evidence=[f"{client_ip} — feed={ip_match.feed}, snapshot={ip_match.snapshot_date}"],
                severity=Severity.HIGH,
                score=60,
            )
        )

    return indicators
