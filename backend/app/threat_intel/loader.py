"""Multi-feed threat-intelligence enrichment (Stage 1) — loads committed, normalized
snapshot files (app/threat_intel/data/*.txt, produced by scripts/refresh_threat_intel.py)
into fast in-memory lookups. No network calls anywhere in this module or its callers; the
snapshots are static, point-in-time data, same architecture as
app.indicators.lookalike_domain's curated brand list.

Each snapshot file's first line is `# snapshot_date: YYYY-MM-DD` (all three files share one
date — one refresh run produces all of them together), followed by `feed_id<TAB>value` rows.
Missing or empty files degrade to empty lookups — same missing-artifact-degrades-gracefully
contract as app.ml.classifier — never raise, since a stale or absent snapshot should silently
disable this signal, not break analysis.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

_DATA_DIR = Path(__file__).parent / "data"
_HOSTNAMES_PATH = _DATA_DIR / "hostnames.txt"
_URLS_PATH = _DATA_DIR / "urls.txt"
_IPS_PATH = _DATA_DIR / "ips.txt"

_IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass(frozen=True)
class ThreatIntelMatch:
    feed: str
    value: str
    artifact_type: str  # "hostname" | "url" | "ip"
    snapshot_date: str


@dataclass(frozen=True)
class ThreatIntelSnapshot:
    hostnames: dict[str, str]
    urls: dict[str, str]
    ip_exact: dict[str, str]
    ip_networks: tuple[tuple[_IPNetwork, str], ...]
    snapshot_date: str


def _read_snapshot_file(path: Path) -> tuple[str | None, dict[str, str]]:
    """Returns (snapshot_date, {value: feed_id}). (None, {}) if the file is missing/empty."""
    if not path.exists():
        return None, {}

    lines = path.read_text(encoding="utf-8").splitlines()
    snapshot_date: str | None = None
    entries: dict[str, str] = {}

    for line in lines:
        line = line.strip()
        if not line:
            continue
        if line.startswith("#"):
            if snapshot_date is None and "snapshot_date:" in line:
                snapshot_date = line.split("snapshot_date:", 1)[1].strip()
            continue
        if "\t" not in line:
            continue
        feed_id, _, value = line.partition("\t")
        value = value.strip().lower()
        if feed_id and value:
            entries.setdefault(value, feed_id.strip())

    return snapshot_date, entries


def _split_ip_entries(raw: dict[str, str]) -> tuple[dict[str, str], tuple[tuple[_IPNetwork, str], ...]]:
    exact: dict[str, str] = {}
    networks: list[tuple[_IPNetwork, str]] = []
    for value, feed_id in raw.items():
        if "/" in value:
            try:
                networks.append((ipaddress.ip_network(value, strict=False), feed_id))
            except ValueError:
                continue
        else:
            exact[value] = feed_id
    return exact, tuple(networks)


@lru_cache(maxsize=1)
def load_snapshot() -> ThreatIntelSnapshot:
    host_date, hostnames = _read_snapshot_file(_HOSTNAMES_PATH)
    url_date, urls = _read_snapshot_file(_URLS_PATH)
    ip_date, raw_ips = _read_snapshot_file(_IPS_PATH)
    ip_exact, ip_networks = _split_ip_entries(raw_ips)

    snapshot_date = host_date or url_date or ip_date or "unknown"

    return ThreatIntelSnapshot(
        hostnames=hostnames,
        urls=urls,
        ip_exact=ip_exact,
        ip_networks=ip_networks,
        snapshot_date=snapshot_date,
    )


def match_hostname(hostname: str | None, snapshot: ThreatIntelSnapshot | None = None) -> ThreatIntelMatch | None:
    if not hostname:
        return None
    snap = snapshot if snapshot is not None else load_snapshot()
    normalized = hostname.strip().lower()
    feed = snap.hostnames.get(normalized)
    if feed is None:
        return None
    return ThreatIntelMatch(feed=feed, value=normalized, artifact_type="hostname", snapshot_date=snap.snapshot_date)


def match_url(url: str | None, snapshot: ThreatIntelSnapshot | None = None) -> ThreatIntelMatch | None:
    if not url:
        return None
    snap = snapshot if snapshot is not None else load_snapshot()
    normalized = url.strip().lower()
    feed = snap.urls.get(normalized)
    if feed is None:
        return None
    return ThreatIntelMatch(feed=feed, value=normalized, artifact_type="url", snapshot_date=snap.snapshot_date)


def match_ip(ip: str | None, snapshot: ThreatIntelSnapshot | None = None) -> ThreatIntelMatch | None:
    if not ip:
        return None
    snap = snapshot if snapshot is not None else load_snapshot()
    normalized = ip.strip()

    feed = snap.ip_exact.get(normalized)
    if feed is not None:
        return ThreatIntelMatch(feed=feed, value=normalized, artifact_type="ip", snapshot_date=snap.snapshot_date)

    try:
        parsed = ipaddress.ip_address(normalized)
    except ValueError:
        return None

    for network, feed_id in snap.ip_networks:
        if parsed in network:
            return ThreatIntelMatch(feed=feed_id, value=normalized, artifact_type="ip", snapshot_date=snap.snapshot_date)
    return None
