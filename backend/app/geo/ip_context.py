"""Builds the display context for one IP: country geolocation (app.geo.lookup) plus any
match in the bundled threat-intel snapshot (app.threat_intel.loader). Shared by the email
sender-IP panel and the activity-log/incident/early-warning views so every IP is labeled
the same way everywhere. Offline only. Display only: nothing here affects a score."""

from __future__ import annotations

import ipaddress

from app.core.config import settings
from app.geo.countries import COUNTRY_NAMES
from app.geo.lookup import GeoDataset, lookup_country
from app.models.schemas import IpContext, IpGeo, IpThreatIntel
from app.threat_intel.loader import ThreatIntelSnapshot, match_ip

_FEED_LABELS = {"tor_exit_node": "Tor exit node"}


def feed_label(feed: str) -> str:
    return _FEED_LABELS.get(feed, f"Known-bad ({feed})")


def geo_for_ip(ip: str | None, dataset: GeoDataset | None = None) -> IpGeo:
    result = lookup_country(ip, dataset)
    return IpGeo(
        status=result.status,
        country_code=result.country_code,
        country_name=result.country_name,
        source="db-ip" if result.status == "resolved" else None,
        snapshot=result.snapshot,
    )


def threat_intel_for_ip(ip: str | None, snapshot: ThreatIntelSnapshot | None = None) -> IpThreatIntel | None:
    # Same switch that gates the scored threat-intel indicators/detections, so an account that
    # has threat-intel off never sees a feed label it wouldn't see as a finding.
    if not settings.enable_threat_intel_indicators:
        return None
    match = match_ip(ip, snapshot)
    if match is None:
        return None
    return IpThreatIntel(feed=match.feed, label=feed_label(match.feed), snapshot_date=match.snapshot_date)


def describe_ip(
    ip: str | None,
    *,
    log_country: str | None = None,
    dataset: GeoDataset | None = None,
    snapshot: ThreatIntelSnapshot | None = None,
) -> IpContext | None:
    """None if `ip` is empty or not a valid IP address.

    `log_country` is a country the source log itself supplied (activity events). When present
    it's shown as-is, labeled source="log", because that's what detections actually use. The
    DB-IP lookup only fills in when the log gave none; it never overrides log data."""
    if not ip:
        return None
    cleaned = ip.strip().strip("[]")
    try:
        ipaddress.ip_address(cleaned)
    except ValueError:
        return None

    if log_country and log_country.strip():
        supplied = log_country.strip()
        code = supplied.upper() if supplied.upper() in COUNTRY_NAMES else None
        geo = IpGeo(
            status="resolved",
            country_code=code,
            country_name=COUNTRY_NAMES[code] if code else supplied,
            source="log",
        )
    else:
        geo = geo_for_ip(cleaned, dataset)
    return IpContext(ip=cleaned, geo=geo, threat_intel=threat_intel_for_ip(cleaned, snapshot))
