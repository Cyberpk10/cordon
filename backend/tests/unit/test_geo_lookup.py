"""Offline IP -> country lookup (app.geo.lookup) and the shared IP display context
(app.geo.ip_context). Logic tests run against a tiny synthetic snapshot written in the real
file format; a couple of sanity checks run against the bundled DB-IP snapshot."""

from __future__ import annotations

import gzip
from pathlib import Path

import pytest

from app.geo.ip_context import describe_ip, feed_label
from app.geo.lookup import default_dataset, load_dataset, lookup_country
from app.threat_intel.loader import ThreatIntelSnapshot


def _write_snapshot(path: Path, v4: list[tuple[int, str]], v6: list[tuple[int, str]]) -> Path:
    lines = ["# snapshot: 2099-01"]
    for fam, rows in ((4, v4), (6, v6)):
        prev = 0
        for start, code in rows:
            lines.append(f"{fam}\t{start - prev}\t{code}")
            prev = start
    with gzip.open(path, "wt", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    return path


def _ip_int(s: str) -> int:
    import ipaddress

    return int(ipaddress.ip_address(s))


@pytest.fixture()
def tiny_dataset(tmp_path):
    path = _write_snapshot(
        tmp_path / "ranges.tsv.gz",
        v4=[
            (0, "ZZ"),
            (_ip_int("8.0.0.0"), "US"),
            (_ip_int("9.0.0.0"), "ZZ"),
            (_ip_int("77.88.0.0"), "RU"),
            (_ip_int("77.89.0.0"), "ZZ"),
            (_ip_int("102.89.0.0"), "NG"),
            (_ip_int("102.90.0.0"), "QQ"),  # a code we have no name for
            (_ip_int("102.91.0.0"), "ZZ"),
        ],
        v6=[(0, "ZZ"), (_ip_int("2a00::"), "DE"), (_ip_int("2b00::"), "ZZ")],
    )
    return load_dataset(path)


def test_resolves_country_name_and_code(tiny_dataset):
    r = lookup_country("8.8.8.8", tiny_dataset)
    assert (r.status, r.country_code, r.country_name, r.snapshot) == ("resolved", "US", "United States", "2099-01")
    assert lookup_country("77.88.55.60", tiny_dataset).country_name == "Russia"
    assert lookup_country("102.89.33.14", tiny_dataset).country_name == "Nigeria"


def test_range_boundaries(tiny_dataset):
    assert lookup_country("8.0.0.0", tiny_dataset).country_code == "US"
    assert lookup_country("8.255.255.255", tiny_dataset).country_code == "US"
    assert lookup_country("9.0.0.0", tiny_dataset).status == "unknown"


def test_ipv6_and_ipv4_mapped(tiny_dataset):
    assert lookup_country("2a00:1450:4864:20::536", tiny_dataset).country_code == "DE"
    assert lookup_country("::ffff:8.8.8.8", tiny_dataset).country_code == "US"


def test_zz_range_is_unknown_never_guessed(tiny_dataset):
    r = lookup_country("100.1.2.3", tiny_dataset)
    assert r.status == "unknown"
    assert r.country_code is None and r.country_name is None


def test_unnamed_code_falls_back_to_the_code_not_a_guess(tiny_dataset):
    r = lookup_country("102.90.1.1", tiny_dataset)
    assert r.status == "resolved"
    assert r.country_name == "QQ"


@pytest.mark.parametrize("ip", ["10.1.2.3", "192.168.0.1", "127.0.0.1", "169.254.1.1", "198.51.100.7", "::1", "fe80::1"])
def test_non_public_addresses(ip, tiny_dataset):
    assert lookup_country(ip, tiny_dataset).status == "non_public"


@pytest.mark.parametrize("ip", [None, "", "garbage", "999.1.1.1", "1.2.3"])
def test_invalid_input_is_unknown(ip, tiny_dataset):
    assert lookup_country(ip, tiny_dataset).status == "unknown"


def test_missing_snapshot_degrades_to_unknown(tmp_path):
    ds = load_dataset(tmp_path / "does-not-exist.tsv.gz")
    assert ds.is_empty
    assert lookup_country("8.8.8.8", ds).status == "unknown"


def test_corrupt_snapshot_degrades_to_unknown(tmp_path):
    bad = tmp_path / "bad.tsv.gz"
    bad.write_bytes(b"not gzip at all")
    assert lookup_country("8.8.8.8", load_dataset(bad)).status == "unknown"


# ---- bundled DB-IP snapshot sanity ---------------------------------------------------------


def test_bundled_snapshot_loads_and_resolves_well_known_ips():
    ds = default_dataset()
    assert not ds.is_empty, "app/geo/data/country_ranges.tsv.gz missing — run scripts/refresh_geoip.py"
    assert ds.snapshot
    assert lookup_country("8.8.8.8").country_code == "US"
    assert lookup_country("10.0.0.1").status == "non_public"


# ---- describe_ip: geo + threat intel + log precedence -------------------------------------


def _snapshot_with(ip: str, feed: str) -> ThreatIntelSnapshot:
    return ThreatIntelSnapshot(hostnames={}, urls={}, ip_exact={ip: feed}, ip_networks=(), snapshot_date="2099-01-01")


def test_describe_ip_includes_tor_label(tiny_dataset):
    ctx = describe_ip("77.88.55.60", dataset=tiny_dataset, snapshot=_snapshot_with("77.88.55.60", "tor_exit_node"))
    assert ctx.geo.country_name == "Russia"
    assert ctx.geo.source == "db-ip"
    assert ctx.threat_intel.label == "Tor exit node"
    assert ctx.threat_intel.feed == "tor_exit_node"


def test_describe_ip_no_match_has_no_threat_intel(tiny_dataset):
    empty = ThreatIntelSnapshot({}, {}, {}, (), "2099-01-01")
    assert describe_ip("8.8.8.8", dataset=tiny_dataset, snapshot=empty).threat_intel is None


def test_threat_intel_label_respects_the_feature_flag(monkeypatch, tiny_dataset):
    from app.core.config import settings

    monkeypatch.setattr(settings, "enable_threat_intel_indicators", False)
    ctx = describe_ip("77.88.55.60", dataset=tiny_dataset, snapshot=_snapshot_with("77.88.55.60", "tor_exit_node"))
    assert ctx.threat_intel is None


def test_unknown_feed_gets_generic_known_bad_label():
    assert feed_label("some_feed") == "Known-bad (some_feed)"


def test_log_supplied_country_wins_and_is_labeled_as_log(tiny_dataset):
    ctx = describe_ip("8.8.8.8", log_country="Nigeria", dataset=tiny_dataset)
    assert ctx.geo.country_name == "Nigeria"
    assert ctx.geo.source == "log"


def test_log_supplied_iso_code_is_expanded(tiny_dataset):
    ctx = describe_ip("8.8.8.8", log_country="gb", dataset=tiny_dataset)
    assert (ctx.geo.country_code, ctx.geo.country_name, ctx.geo.source) == ("GB", "United Kingdom", "log")


def test_describe_ip_rejects_non_ips():
    assert describe_ip(None) is None
    assert describe_ip("") is None
    assert describe_ip("mail.example.com") is None
