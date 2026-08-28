"""DNS TXT record lookup for simulation domain-control verification (M9 Stage 1), via
DNS-over-HTTPS over `httpx` rather than a raw-socket DNS library (`dnspython`) — matches this
codebase's existing convention that every network call is httpx-based and mockable with
`respx` in tests (see app.autonomy.graph_connector, app.inbound.mailgun), instead of
introducing a second, incompatible mocking story just for this one feature.

This is a deliberate, narrow exception to the app's general "no live DNS lookups" posture
(see app.parsing.auth_results) — the one and only purpose here is proving domain control for
phishing-simulation targeting, nothing else gains a live DNS dependency.
"""

from __future__ import annotations

import httpx

from app.core.config import settings

_TXT_RECORD_TYPE = "TXT"
_RECORD_PREFIX = "_cordon-verify"
_VALUE_PREFIX = "cordon-domain-verification="


def verification_record_name(domain: str) -> str:
    return f"{_RECORD_PREFIX}.{domain}"


def verification_record_value(verification_token: str) -> str:
    return f"{_VALUE_PREFIX}{verification_token}"


def resolve_txt(name: str) -> list[str]:
    """Returns the TXT record values published for `name`, or an empty list on any lookup
    failure or malformed response — never raises. A verification check failing to find a
    match is always treated as "not verified yet" (a normal, expected outcome while DNS
    propagates), never as a 500."""
    try:
        response = httpx.get(
            settings.simulation_dns_over_https_url,
            params={"name": name, "type": _TXT_RECORD_TYPE},
            headers={"Accept": "application/dns-json"},
            timeout=10,
        )
        response.raise_for_status()
        payload = response.json()
    except (httpx.HTTPError, ValueError):
        return []

    answers = payload.get("Answer") or []
    values: list[str] = []
    for answer in answers:
        data = answer.get("data")
        if not isinstance(data, str):
            continue
        # DoH resolvers wrap TXT data in a surrounding quote pair (and may concatenate
        # multiple quoted chunks for long records) — strip one pair if present.
        if data.startswith('"') and data.endswith('"') and len(data) >= 2:
            data = data[1:-1]
        values.append(data)
    return values


def domain_is_verified_by(verification_token: str, domain: str) -> bool:
    expected = verification_record_value(verification_token)
    return expected in resolve_txt(verification_record_name(domain))
