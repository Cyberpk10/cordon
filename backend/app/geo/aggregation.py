"""Collapses a set of activity events into their distinct source IPs, each enriched with
country + threat-intel context (app.geo.ip_context). No DB access: callers pass events in
(ORM `Event` rows or `ActivityEvent` models, both work). Used by the Early-Warning list and
the activity-log analyzer summary. Display only: detections never read this.

Country precedence per IP: the country the LOG supplied on that IP's most recent event, if
any (that's what anomalous_location/impossible_travel actually evaluate), otherwise the
offline DB-IP lookup. Resolved geo is never written back to an event.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime
from typing import Any

from app.geo.ip_context import describe_ip
from app.models.schemas import ActorSourceIp

DEFAULT_MAX_IPS = 10


def _log_country(geo: Any) -> str | None:
    if geo is None:
        return None
    if isinstance(geo, dict):
        value = geo.get("country")
    else:
        value = getattr(geo, "country", None)
    return value.strip() if isinstance(value, str) and value.strip() else None


def summarize_source_ips(events: Iterable[Any], max_ips: int = DEFAULT_MAX_IPS) -> list[ActorSourceIp]:
    """Distinct IPs, most-active first (ties: most recent first), capped at `max_ips`.
    Events without a valid source_ip are skipped."""
    stats: dict[str, dict[str, Any]] = {}
    for event in events:
        ip = (getattr(event, "source_ip", None) or "").strip()
        if not ip:
            continue
        ts: datetime | None = getattr(event, "timestamp", None)
        entry = stats.setdefault(ip, {"count": 0, "last_seen": None, "log_country": None})
        entry["count"] += 1
        if ts is not None and (entry["last_seen"] is None or ts >= entry["last_seen"]):
            entry["last_seen"] = ts
            country = _log_country(getattr(event, "geo", None))
            if country:
                entry["log_country"] = country
        elif entry["log_country"] is None:
            entry["log_country"] = _log_country(getattr(event, "geo", None))

    ordered = sorted(
        stats.items(),
        key=lambda kv: (kv[1]["count"], kv[1]["last_seen"] or datetime.min),
        reverse=True,
    )
    out: list[ActorSourceIp] = []
    for ip, entry in ordered:
        ctx = describe_ip(ip, log_country=entry["log_country"])
        if ctx is None:
            continue
        out.append(
            ActorSourceIp(
                ip=ctx.ip,
                geo=ctx.geo,
                threat_intel=ctx.threat_intel,
                event_count=entry["count"],
                last_seen=entry["last_seen"],
            )
        )
        if len(out) >= max_ips:
            break
    return out
