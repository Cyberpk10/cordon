"""Assembles the display-only SenderIpInfo for a parsed email: SPF client-ip from
Authentication-Results or Received-SPF (higher confidence), falling back to the topmost
external Received hop (lower confidence), plus X-Originating-IP and the full parsed hop list.
Each IP is enriched with country geolocation and threat-intel labels via app.geo.ip_context.

NEVER feeds scoring. See app.parsing.received_chain's docstring for why: header-derived IPs
are partly forgeable and often belong to the mail provider, not the attacker.
"""

from __future__ import annotations

from app.channels.message import Channel, Message
from app.geo.ip_context import describe_ip
from app.models.schemas import ReceivedHopInfo, SenderIpInfo
from app.parsing.auth_results import extract_spf_client_ip
from app.parsing.received_chain import (
    extract_originating_ip,
    extract_received_spf_client_ip,
    parse_received_chain,
    pick_received_sending_hop,
)


def build_sender_ip_info(parsed: Message) -> SenderIpInfo | None:
    """None for non-email channels, or when the headers carry no IP information at all (e.g.
    a pasted body-only fragment). Never raises on odd headers: every parser it calls skips
    what it can't read."""
    if parsed.channel != Channel.EMAIL:
        return None

    hops = parse_received_chain(parsed.received_headers)
    spf_ip = extract_spf_client_ip(parsed.auth_results.raw_header) or extract_received_spf_client_ip(
        parsed.received_spf_header
    )
    originating_ip = extract_originating_ip(parsed.originating_ip_header)

    sending_ip = None
    source = None
    confidence = None
    if spf_ip:
        sending_ip = describe_ip(spf_ip)
        source, confidence = "spf_client_ip", "higher"
    if sending_ip is None:
        hop = pick_received_sending_hop(hops)
        if hop is not None and hop.ip:
            sending_ip = describe_ip(hop.ip)
            if sending_ip is not None:
                source, confidence = "received_chain", "lower"

    originating = describe_ip(originating_ip) if originating_ip else None

    if sending_ip is None and originating is None and not hops:
        return None

    return SenderIpInfo(
        sending_ip=sending_ip,
        sending_ip_source=source,
        sending_ip_confidence=confidence,
        originating_ip=originating,
        hops=[
            ReceivedHopInfo(
                index=h.index, from_host=h.from_host, by_host=h.by_host, ip=h.ip, is_public=h.is_public
            )
            for h in hops
        ],
    )
