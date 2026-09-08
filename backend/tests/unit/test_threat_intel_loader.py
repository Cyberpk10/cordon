from __future__ import annotations

from app.threat_intel.loader import (
    ThreatIntelSnapshot,
    _read_snapshot_file,
    _split_ip_entries,
    load_snapshot,
    match_hostname,
    match_ip,
    match_url,
)


def _snapshot(**overrides) -> ThreatIntelSnapshot:
    defaults = dict(hostnames={}, urls={}, ip_exact={}, ip_networks=(), snapshot_date="2026-01-01")
    defaults.update(overrides)
    return ThreatIntelSnapshot(**defaults)


def test_match_hostname_returns_feed_and_snapshot_date():
    snap = _snapshot(hostnames={"evil.example.net": "phishtank"})
    match = match_hostname("EVIL.example.NET", snap)
    assert match is not None
    assert match.feed == "phishtank"
    assert match.artifact_type == "hostname"
    assert match.snapshot_date == "2026-01-01"


def test_match_hostname_none_for_clean_host():
    snap = _snapshot(hostnames={"evil.example.net": "phishtank"})
    assert match_hostname("safe.example.com", snap) is None
    assert match_hostname(None, snap) is None


def test_match_url_exact_match_case_insensitive_on_scheme_host():
    snap = _snapshot(urls={"https://evil.example.net/login": "phishtank"})
    match = match_url("HTTPS://evil.example.net/login", snap)
    assert match is not None
    assert match.feed == "phishtank"
    assert match.artifact_type == "url"


def test_match_ip_exact():
    snap = _snapshot(ip_exact={"203.0.113.5": "tor_exit_node"})
    match = match_ip("203.0.113.5", snap)
    assert match is not None
    assert match.feed == "tor_exit_node"
    assert match.artifact_type == "ip"


def test_match_ip_cidr_containment():
    import ipaddress

    snap = _snapshot(ip_networks=((ipaddress.ip_network("198.51.100.0/24"), "some_feed"),))
    match = match_ip("198.51.100.42", snap)
    assert match is not None
    assert match.feed == "some_feed"
    assert match_ip("203.0.113.1", snap) is None


def test_match_ip_invalid_string_returns_none():
    snap = _snapshot()
    assert match_ip("not-an-ip", snap) is None


def test_split_ip_entries_separates_exact_and_cidr():
    exact, networks = _split_ip_entries({"203.0.113.5": "tor_exit_node", "198.51.100.0/24": "some_feed"})
    assert exact == {"203.0.113.5": "tor_exit_node"}
    assert len(networks) == 1
    assert str(networks[0][0]) == "198.51.100.0/24"


def test_read_snapshot_file_missing_returns_none_and_empty(tmp_path):
    date, entries = _read_snapshot_file(tmp_path / "does_not_exist.txt")
    assert date is None
    assert entries == {}


def test_read_snapshot_file_parses_header_and_rows(tmp_path):
    f = tmp_path / "hostnames.txt"
    f.write_text("# snapshot_date: 2026-05-01\nphishtank\tevil.example.net\n# comment\n\n")
    date, entries = _read_snapshot_file(f)
    assert date == "2026-05-01"
    assert entries == {"evil.example.net": "phishtank"}


def test_load_snapshot_degrades_gracefully_when_files_absent(monkeypatch):
    load_snapshot.cache_clear()
    monkeypatch.setattr("app.threat_intel.loader._HOSTNAMES_PATH", __import__("pathlib").Path("/nonexistent/hostnames.txt"))
    monkeypatch.setattr("app.threat_intel.loader._URLS_PATH", __import__("pathlib").Path("/nonexistent/urls.txt"))
    monkeypatch.setattr("app.threat_intel.loader._IPS_PATH", __import__("pathlib").Path("/nonexistent/ips.txt"))
    snap = load_snapshot()
    assert snap.hostnames == {}
    assert snap.urls == {}
    assert snap.ip_exact == {}
    assert snap.ip_networks == ()
    load_snapshot.cache_clear()
