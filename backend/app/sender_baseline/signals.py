"""How one email was sent, from its headers. Pure: no DB, no network (the geo lookup reads
the bundled offline snapshot).

Reuses the source-IP display code (app.parsing.received_chain, app.parsing.auth_results) and
the offline country lookup (app.geo.lookup). Unlike app.analysis.sender_ip, the result here
does feed a scored rule (app.indicators.account_takeover), but only for mail that passed
authentication as an established sender and asks for something sensitive. See that module.

Which IP the country comes from, in order:
  1. X-Originating-IP ("originating"): the submitting client, recorded by the sender's own
     provider. This is the one that can reveal an attacker's location, but many providers
     (Gmail, current Microsoft 365) don't add it.
  2. The SPF client-ip the receiver stamped ("spf_client_ip").
  3. The topmost external Received hop ("received_chain").
(2) and (3) are usually the sending provider's own server, so for hosted mailboxes they track
the provider's infrastructure, not the person. Countries are only ever compared with prior
countries from the same source.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timezone
from email.utils import parseaddr, parsedate_to_datetime

from app.channels.message import Channel, Message
from app.geo.lookup import lookup_country
from app.indicators.domain_utils import registrable_domain
from app.models.schemas import AuthResultValue
from app.parsing.auth_results import extract_spf_client_ip
from app.parsing.received_chain import (
    extract_originating_ip,
    extract_received_spf_client_ip,
    parse_received_chain,
    pick_received_sending_hop,
    provider_of,
)

_AUTH_FAILURES = {AuthResultValue.FAIL, AuthResultValue.SOFTFAIL, AuthResultValue.PERMERROR}


@dataclass(frozen=True)
class MessageSignals:
    from_addr: str
    from_domain: str
    message_hour_utc: int | None
    sending_ip: str | None
    sending_country: str | None  # ISO code, only when the lookup resolved
    sending_country_name: str | None
    country_source: str | None  # "originating" | "spf_client_ip" | "received_chain"
    sending_provider: str | None
    reply_to_domain: str | None
    return_path_domain: str | None
    auth_pass: bool


def _domain_of_address(address: str | None) -> str | None:
    if not address or "@" not in address:
        return None
    host = address.rsplit("@", 1)[-1].strip().lower().rstrip(">")
    return registrable_domain(host) if host else None


def _header(email: Message, name: str) -> str | None:
    lower = name.lower()
    for key, value in email.headers.items():
        if key.lower() == lower:
            return value
    return None


def _hour_utc(date_header: str | None) -> int | None:
    if not date_header:
        return None
    try:
        dt = parsedate_to_datetime(date_header)
    except (TypeError, ValueError, IndexError):
        return None
    if dt is None or dt.tzinfo is None:
        return None  # no zone: the hour would be a guess
    return dt.astimezone(timezone.utc).hour


def authenticates_as_sender(email: Message) -> bool:
    """DMARC pass, or SPF and DKIM both pass, with none of the three failing. DMARC pass is
    the precise "this is really the From domain" result; SPF+DKIM is the fallback for
    receivers that don't report DMARC."""
    auth = email.auth_results
    if {auth.spf, auth.dkim, auth.dmarc} & _AUTH_FAILURES:
        return False
    if auth.dmarc == AuthResultValue.PASS:
        return True
    return auth.spf == AuthResultValue.PASS and auth.dkim == AuthResultValue.PASS


def extract_signals(email: Message) -> MessageSignals | None:
    """None for chat messages and for email with no usable From address."""
    if email.channel != Channel.EMAIL or not email.from_address or "@" not in email.from_address:
        return None
    from_addr = email.from_address.strip().lower()
    from_domain = _domain_of_address(from_addr)
    if not from_domain:
        return None

    hops = parse_received_chain(email.received_headers)
    hop = pick_received_sending_hop(hops)
    spf_ip = extract_spf_client_ip(email.auth_results.raw_header) or extract_received_spf_client_ip(
        email.received_spf_header
    )
    candidates = [
        ("originating", extract_originating_ip(email.originating_ip_header)),
        ("spf_client_ip", spf_ip),
        ("received_chain", hop.ip if hop else None),
    ]

    sending_ip = country = country_name = source = None
    for candidate_source, ip in candidates:
        if not ip:
            continue
        geo = lookup_country(ip)
        if geo.status == "resolved":
            sending_ip, country, country_name, source = ip, geo.country_code, geo.country_name, candidate_source
            break
        if sending_ip is None:
            sending_ip = ip  # keep the IP even when it has no country

    _, return_path = parseaddr(_header(email, "Return-Path") or "")
    return MessageSignals(
        from_addr=from_addr,
        from_domain=from_domain,
        message_hour_utc=_hour_utc(email.date),
        sending_ip=sending_ip,
        sending_country=country,
        sending_country_name=country_name,
        country_source=source,
        sending_provider=provider_of(hop.from_host) if hop else None,
        reply_to_domain=_domain_of_address(email.reply_to_address),
        return_path_domain=_domain_of_address(return_path),
        auth_pass=authenticates_as_sender(email),
    )
