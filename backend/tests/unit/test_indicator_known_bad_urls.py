from __future__ import annotations

from app.core.config import settings
from app.indicators import known_bad_urls
from app.parsing.eml_parser import Link, ParsedEmail
from app.scoring.risk_engine import fuse
from app.threat_intel import loader as threat_intel_loader
from app.threat_intel.loader import ThreatIntelSnapshot


def _snapshot(**overrides) -> ThreatIntelSnapshot:
    defaults = dict(hostnames={}, urls={}, ip_exact={}, ip_networks=(), snapshot_date="2026-05-01")
    defaults.update(overrides)
    return ThreatIntelSnapshot(**defaults)


def _patch_snapshot(monkeypatch, snap: ThreatIntelSnapshot) -> None:
    """Patches known_bad_urls's own bound names (it does `from ... import match_hostname,
    match_url`), same monkeypatch seam the module's docstring/design assumes."""
    monkeypatch.setattr(known_bad_urls, "match_hostname", lambda h: threat_intel_loader.match_hostname(h, snap))
    monkeypatch.setattr(known_bad_urls, "match_url", lambda u: threat_intel_loader.match_url(u, snap))


def test_flags_link_matching_known_malicious_hostname(monkeypatch):
    snap = _snapshot(hostnames={"evil-phish.example": "phishtank"})
    _patch_snapshot(monkeypatch, snap)
    email = ParsedEmail(
        links=[Link(display_text="click", href="https://evil-phish.example/x", href_domain="evil-phish.example")]
    )
    indicators = known_bad_urls.evaluate(email)
    ids = {i.id for i in indicators}
    assert "LINK_KNOWN_MALICIOUS" in ids
    assert any("phishtank" in e and "2026-05-01" in e for e in indicators[0].evidence)


def test_flags_link_matching_known_malicious_url(monkeypatch):
    snap = _snapshot(urls={"https://cdn.example.net/bad-path": "phishtank"})
    _patch_snapshot(monkeypatch, snap)
    email = ParsedEmail(
        links=[Link(display_text="click", href="https://cdn.example.net/bad-path", href_domain="cdn.example.net")]
    )
    ids = {i.id for i in known_bad_urls.evaluate(email)}
    assert "LINK_KNOWN_MALICIOUS" in ids


def test_no_flag_for_link_not_in_any_feed(monkeypatch):
    snap = _snapshot(hostnames={"evil-phish.example": "phishtank"})
    _patch_snapshot(monkeypatch, snap)
    email = ParsedEmail(
        links=[Link(display_text="click", href="https://safe.example/x", href_domain="safe.example")]
    )
    assert known_bad_urls.evaluate(email) == []


def test_disabled_via_settings_flag(monkeypatch):
    monkeypatch.setattr(settings, "enable_threat_intel_indicators", False)
    snap = _snapshot(hostnames={"evil-phish.example": "phishtank"})
    _patch_snapshot(monkeypatch, snap)
    email = ParsedEmail(
        links=[Link(display_text="click", href="https://evil-phish.example/x", href_domain="evil-phish.example")]
    )
    assert known_bad_urls.evaluate(email) == []


def test_known_bad_link_match_alone_pushes_verdict_to_malicious(monkeypatch):
    snap = _snapshot(hostnames={"evil-phish.example": "phishtank"})
    _patch_snapshot(monkeypatch, snap)
    email = ParsedEmail(
        links=[Link(display_text="click", href="https://evil-phish.example/x", href_domain="evil-phish.example")]
    )
    indicators = known_bad_urls.evaluate(email)
    score, verdict = fuse(indicators)
    assert verdict.value == "malicious"
