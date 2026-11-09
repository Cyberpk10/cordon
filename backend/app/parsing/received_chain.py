"""Parses an email's `Received:` header chain and `X-Originating-IP` into hops, and picks the
sending IP for DISPLAY. Pure: no I/O, no network, no DNS.

DISPLAY-ONLY, never scored. app.indicators.known_bad_sender rejected Received-chain parsing
for scoring because the chain is partly attacker-controlled (everything below the receiver's
own edge can be forged) and formats vary widely by provider. That reasoning still holds, so
nothing here feeds an indicator or the risk score. What's surfaced is information for an
analyst, clearly labeled with its source and confidence:

  1. SPF `client-ip` the receiving server stamped, from Authentication-Results or, failing
     that, the topmost `Received-SPF:` header (Gmail and Microsoft 365 put it only there).
     The IP that actually connected to the receiver, as the receiver itself saw it. "higher"
     confidence, though a receiver that adds neither header leaves a forged one unchallenged.
  2. Fallback: the topmost Received hop whose `from` clause names a public IP, skipping hops
     that are a provider's internal hand-off (from-host and by-host share a registrable
     domain, e.g. Microsoft 365's *.prod.outlook.com relays). "lower" confidence.
  3. `X-Originating-IP`, shown separately: some providers record the submitting client's IP
     here. Provider-reported and easily forged by direct-to-MX senders.

Either way it's often the mail provider's server, not the attacker's machine.

Header formats this handles (from real provider samples, see tests/fixtures/received/):
    from host (host. [203.0.113.5]) by mx...              Gmail, Postfix, Sendmail
    from host (host [203.0.113.5]:port helo=x) by mx...   Exim
    from [203.0.113.5] (helo=x) by mx...                  Exim, bare literal
    from host (2603:10a6:20b:2f0::12) by host2 (...)      Microsoft 365 internal hops
    from unknown (HELO x) (203.0.113.5) by mx...          qmail
    from host ([IPv6:2001:db8::1]) by mx...               IPv6 literal
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

MAX_HOPS = 25

# The `from` clause runs from a leading "from" up to the first " by " keyword. Some Received
# headers (e.g. the receiver's own local delivery) have no from clause at all.
_FROM_CLAUSE_RE = re.compile(r"^\s*from\s+(.*?)(?:\s+by\s+|;|$)", re.IGNORECASE | re.DOTALL)
_BY_HOST_RE = re.compile(r"\sby\s+([^\s;()]+)", re.IGNORECASE)
_BRACKETED_RE = re.compile(r"\[(?:IPv6:)?([0-9A-Fa-f:.]+)\](?::\d+)?")
_PAREN_BARE_RE = re.compile(r"\(\s*([0-9A-Fa-f:.]{3,})\s*\)")
_HOST_RE = re.compile(r"^([A-Za-z0-9._:-]+)")

# Registrable domains one provider uses interchangeably for its own internal relays, so a
# hand-off between them is still "inside the provider" (e.g. Microsoft 365 hops between
# *.prod.outlook.com and *.outlook.office365.com before final delivery).
_PROVIDER_ALIASES = {
    "office365.com": "outlook.com",
    "outlook.com": "outlook.com",
    "googlemail.com": "google.com",
    "gmail.com": "google.com",
    "google.com": "google.com",
}


@dataclass(frozen=True)
class ReceivedHop:
    index: int  # 0 = topmost header = most recent hop (added by the final receiver)
    from_host: str | None
    by_host: str | None
    ip: str | None
    is_public: bool


def _valid_ip(candidate: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        addr = ipaddress.ip_address(candidate.strip())
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    return addr


def _ip_from_clause(clause: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    # A bracketed literal is the connecting IP the receiving MTA recorded (the TCP peer), so
    # it wins over anything else in the clause, such as an IP-looking HELO string.
    for match in _BRACKETED_RE.finditer(clause):
        addr = _valid_ip(match.group(1))
        if addr is not None:
            return addr
    for match in _PAREN_BARE_RE.finditer(clause):
        addr = _valid_ip(match.group(1))
        if addr is not None:
            return addr
    return None


def _clean_host(raw: str | None) -> str | None:
    if not raw:
        return None
    m = _HOST_RE.match(raw.strip())
    if not m:
        return None
    host = m.group(1).rstrip(".").lower()
    if not host or _valid_ip(host) is not None:
        return None  # an IP literal isn't a hostname (e.g. Gmail's "by 2002:a05:...")
    return host.split(":", 1)[0] or None


def parse_hop(index: int, header: str) -> ReceivedHop:
    flat = " ".join(header.split())
    from_match = _FROM_CLAUSE_RE.match(flat)
    clause = from_match.group(1) if from_match else ""
    addr = _ip_from_clause(clause) if clause else None
    from_host = _clean_host(clause) if clause and not clause.lstrip().startswith(("[", "(")) else None
    by_match = _BY_HOST_RE.search(" " + flat)
    by_host = _clean_host(by_match.group(1)) if by_match else None
    return ReceivedHop(
        index=index,
        from_host=from_host,
        by_host=by_host,
        ip=str(addr) if addr is not None else None,
        is_public=bool(addr is not None and addr.is_global),
    )


def parse_received_chain(headers: list[str]) -> list[ReceivedHop]:
    return [parse_hop(i, h) for i, h in enumerate(headers[:MAX_HOPS])]


def _registrable(host: str | None) -> str | None:
    if not host or _valid_ip(host) is not None:
        return None
    labels = host.split(".")
    if len(labels) < 2:
        return None
    # Two-label suffix is a deliberate simplification (no public-suffix list bundled): it
    # only decides whether a hop looks like an internal hand-off to skip in the display
    # fallback, and on a miss the hop is still listed in full for the analyst.
    base = ".".join(labels[-2:])
    return _PROVIDER_ALIASES.get(base, base)


def _is_internal_handoff(hop: ReceivedHop) -> bool:
    a, b = _registrable(hop.from_host), _registrable(hop.by_host)
    return a is not None and a == b


def pick_received_sending_hop(hops: list[ReceivedHop]) -> ReceivedHop | None:
    """Topmost hop with a public IP that isn't a same-provider internal relay. If every public
    hop looks internal (e.g. Gmail-to-Gmail: google.com -> mx.google.com), the topmost public
    hop is still the best available answer: the provider's own outbound server."""
    public = [h for h in hops if h.is_public]
    for hop in public:
        if not _is_internal_handoff(hop):
            return hop
    return public[0] if public else None


def extract_originating_ip(value: str | None) -> str | None:
    """`X-Originating-IP: [203.0.113.5]` -> "203.0.113.5". None if absent or invalid."""
    if not value:
        return None
    addr = _valid_ip(value.strip().strip("[]").split(",")[0])
    return str(addr) if addr is not None else None


def extract_received_spf_client_ip(value: str | None) -> str | None:
    """`Received-SPF: pass (...) client-ip=40.107.22.91; helo=...` -> "40.107.22.91"."""
    if not value:
        return None
    m = re.search(r"client-ip=\[?([0-9A-Fa-f:.]+?)\]?(?:[;\s]|$)", value, re.IGNORECASE)
    if not m:
        return None
    addr = _valid_ip(m.group(1))
    return str(addr) if addr is not None else None
