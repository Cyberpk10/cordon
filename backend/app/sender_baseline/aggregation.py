"""Folds one sender's prior observations into a SenderBaseline. Pure: no DB.

Anti-poisoning, the same idea as app.sender_history.aggregation's ESTABLISHED bar:
- Only prior observations that were clean AND authenticated contribute what counts as
  "normal" for this sender (countries, providers, reply-to/return-path domains, hours). An
  earlier malicious or unauthenticated email from the attacker's country can never make that
  country look normal.
- ESTABLISHED needs enough of those trusted observations, spread over real time (reusing
  sender_history_established_min_occurrences / _min_span_days), outnumbering any malicious
  ones. Earlier malicious mail from the address (often the takeover's first strike) doesn't
  revoke a real baseline, so the attacker's next message is still judged against it; mostly-
  malicious history is FLAGGED and gets no baseline.
- The email being analyzed is never part of its own baseline: observations are recorded
  after analysis.
- One sighting never makes a value normal. A country, provider, reply-to or return-path
  domain only becomes "known" after KNOWN_MIN_COUNT trusted observations at least
  KNOWN_MIN_SPAN_DAYS apart. Otherwise a single harmless email from a hijacked account (the
  usual first move) would whitelist the attacker's location for the payment request that
  follows. A sender who really is abroad for a while becomes known there after a day.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal

from app.core.config import settings

BaselineStatus = Literal["first_contact", "building", "established", "flagged"]

KNOWN_MIN_COUNT = 2
KNOWN_MIN_SPAN_DAYS = 1.0


@dataclass(frozen=True)
class ObservationRow:
    observed_at: datetime
    message_hour_utc: int | None
    sending_country: str | None
    country_source: str | None
    sending_provider: str | None
    reply_to_domain: str | None
    return_path_domain: str | None
    auth_pass: bool
    verdict: str  # "safe" | "suspicious" | "malicious"


@dataclass(frozen=True)
class SenderBaseline:
    from_addr: str
    status: BaselineStatus
    message_count: int  # every prior observation
    trusted_count: int  # clean + authenticated ones, the only ones "normal" is built from
    auth_pass_count: int
    first_seen: datetime | None
    last_seen: datetime | None
    # source -> {country code: count}: only KNOWN values (see module docstring), from trusted
    # observations only. Same for providers and the reply-to/return-path domain sets.
    countries: dict[str, dict[str, int]] = field(default_factory=dict)
    providers: dict[str, int] = field(default_factory=dict)
    reply_to_domains: frozenset[str] = frozenset()
    return_path_domains: frozenset[str] = frozenset()
    hours: tuple[int, ...] = ()  # one entry per trusted observation with a known hour
    malicious_count: int = 0


def _known(rows: list[ObservationRow], value_of) -> frozenset[str]:
    """Values seen in at least KNOWN_MIN_COUNT of `rows`, at least KNOWN_MIN_SPAN_DAYS apart."""
    seen: dict[str, list[datetime]] = {}
    for r in rows:
        v = value_of(r)
        if v:
            seen.setdefault(v, []).append(r.observed_at)
    return frozenset(
        v for v, times in seen.items()
        if len(times) >= KNOWN_MIN_COUNT
        and (max(times) - min(times)).total_seconds() / 86400 >= KNOWN_MIN_SPAN_DAYS
    )


def build_baseline(from_addr: str, rows: list[ObservationRow]) -> SenderBaseline:
    if not rows:
        return SenderBaseline(
            from_addr=from_addr, status="first_contact", message_count=0, trusted_count=0,
            auth_pass_count=0, first_seen=None, last_seen=None,
        )

    trusted = [r for r in rows if r.auth_pass and r.verdict == "safe"]
    countries: dict[str, Counter] = {}
    providers: Counter = Counter()
    for r in trusted:
        if r.sending_country and r.country_source:
            countries.setdefault(r.country_source, Counter())[r.sending_country] += 1
        if r.sending_provider:
            providers[r.sending_provider] += 1
    known_countries = {
        src: _known(trusted, lambda r, src=src: r.sending_country if r.country_source == src else None)
        for src in countries
    }
    known_providers = _known(trusted, lambda r: r.sending_provider)

    malicious = sum(1 for r in rows if r.verdict == "malicious")
    span_days = (
        (max(r.observed_at for r in trusted) - min(r.observed_at for r in trusted)).total_seconds() / 86400
        if trusted
        else 0.0
    )
    if (
        len(trusted) >= settings.sender_history_established_min_occurrences
        and span_days >= settings.sender_history_established_min_span_days
        and malicious < len(trusted)
    ):
        status: BaselineStatus = "established"
    elif malicious:
        status = "flagged"
    else:
        status = "building"

    return SenderBaseline(
        from_addr=from_addr,
        status=status,
        message_count=len(rows),
        trusted_count=len(trusted),
        auth_pass_count=sum(1 for r in rows if r.auth_pass),
        first_seen=min(r.observed_at for r in rows),
        last_seen=max(r.observed_at for r in rows),
        countries={
            src: {code: n for code, n in c.items() if code in known_countries[src]}
            for src, c in countries.items()
            if known_countries[src]
        },
        providers={p: n for p, n in providers.items() if p in known_providers},
        reply_to_domains=_known(trusted, lambda r: r.reply_to_domain),
        return_path_domains=_known(trusted, lambda r: r.return_path_domain),
        hours=tuple(r.message_hour_utc for r in trusted if r.message_hour_utc is not None),
        malicious_count=malicious,
    )


def _top(counts: dict[str, int], limit: int = 3) -> list[str]:
    return [k for k, _ in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:limit]]


def usual_countries(baseline: SenderBaseline, source: str | None = None) -> list[str]:
    """Most common country codes, for one IP source or (source=None) all sources merged."""
    if source is not None:
        return _top(baseline.countries.get(source, {}))
    merged: Counter = Counter()
    for counts in baseline.countries.values():
        merged.update(counts)
    return _top(dict(merged))


def usual_providers(baseline: SenderBaseline) -> list[str]:
    return _top(baseline.providers)


def summary_line(baseline: SenderBaseline | None, country_name) -> str:
    """One plain-English line describing what Cordon knows about this sender. Never claims a
    baseline that doesn't exist. `country_name` maps an ISO code to a display name."""
    if baseline is None or baseline.status == "first_contact":
        return "First contact: no baseline for this sender yet."
    need = settings.sender_history_established_min_occurrences
    if baseline.status == "flagged":
        return (
            f"{baseline.message_count} prior message(s) from this sender, {baseline.malicious_count} "
            "of them malicious, so there is no trusted baseline."
        )
    if baseline.status == "building":
        return (
            f"Building a baseline: {baseline.trusted_count} clean, authenticated message(s) so "
            f"far; {need} spread over more than "
            f"{settings.sender_history_established_min_span_days} day(s) are needed."
        )
    parts = [
        f"Known sender: {baseline.message_count} prior messages since "
        f"{baseline.first_seen:%b} {baseline.first_seen.day}, {baseline.first_seen.year}"
    ]
    countries = [country_name(c) for c in usual_countries(baseline)]
    if countries:
        parts.append("usually from " + ", ".join(countries))
    providers = usual_providers(baseline)
    if providers:
        parts.append("sent via " + ", ".join(providers))
    parts.append(
        f"authentication passed on {baseline.auth_pass_count} of {baseline.message_count}"
    )
    if baseline.malicious_count:
        parts.append(f"{baseline.malicious_count} recent message(s) from this address were flagged malicious")
    return "; ".join(parts) + "."


def baseline_summary(baseline: SenderBaseline | None, country_name) -> dict:
    """The structured summary surfaced on the analysis result, the Case and /v1."""
    if baseline is None:
        return {
            "status": "first_contact",
            "summary": summary_line(None, country_name),
            "message_count": 0,
            "trusted_message_count": 0,
            "auth_pass_count": 0,
            "first_seen": None,
            "last_seen": None,
            "usual_countries": [],
            "usual_providers": [],
        }
    return {
        "status": baseline.status,
        "summary": summary_line(baseline, country_name),
        "message_count": baseline.message_count,
        "trusted_message_count": baseline.trusted_count,
        "auth_pass_count": baseline.auth_pass_count,
        "first_seen": baseline.first_seen.isoformat() if baseline.first_seen else None,
        "last_seen": baseline.last_seen.isoformat() if baseline.last_seen else None,
        "usual_countries": [country_name(c) for c in usual_countries(baseline)],
        "usual_providers": usual_providers(baseline),
    }
