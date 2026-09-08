from __future__ import annotations

from app.core.config import settings
from app.indicators import known_bad_sender
from app.models.schemas import AuthResults
from app.parsing.eml_parser import ParsedEmail
from app.threat_intel import loader as threat_intel_loader
from app.threat_intel.loader import ThreatIntelSnapshot


def _snapshot(**overrides) -> ThreatIntelSnapshot:
    defaults = dict(hostnames={}, urls={}, ip_exact={}, ip_networks=(), snapshot_date="2026-05-01")
    defaults.update(overrides)
    return ThreatIntelSnapshot(**defaults)


def _patch_snapshot(monkeypatch, snap: ThreatIntelSnapshot) -> None:
    monkeypatch.setattr(known_bad_sender, "match_hostname", lambda h: threat_intel_loader.match_hostname(h, snap))
    monkeypatch.setattr(known_bad_sender, "match_ip", lambda ip: threat_intel_loader.match_ip(ip, snap))


def test_sender_domain_match_fires(monkeypatch):
    snap = _snapshot(hostnames={"evil-sender.example": "phishtank"})
    _patch_snapshot(monkeypatch, snap)
    email = ParsedEmail(from_address="attacker@evil-sender.example")
    ids = {i.id for i in known_bad_sender.evaluate(email)}
    assert "SENDER_DOMAIN_KNOWN_BAD" in ids


def test_sender_domain_clean_does_not_fire(monkeypatch):
    snap = _snapshot(hostnames={"evil-sender.example": "phishtank"})
    _patch_snapshot(monkeypatch, snap)
    email = ParsedEmail(from_address="person@safe.example.com")
    assert known_bad_sender.evaluate(email) == []


def test_sender_ip_match_fires_via_client_ip_in_auth_header(monkeypatch):
    snap = _snapshot(ip_exact={"203.0.113.5": "tor_exit_node"})
    _patch_snapshot(monkeypatch, snap)
    email = ParsedEmail(
        from_address="person@safe.example.com",
        auth_results=AuthResults(raw_header="spf=pass (example.com: domain designates 203.0.113.5 as permitted sender) client-ip=203.0.113.5"),
    )
    ids = {i.id for i in known_bad_sender.evaluate(email)}
    assert "SENDER_IP_KNOWN_MALICIOUS" in ids


def test_no_client_ip_token_degrades_to_no_finding_not_an_error(monkeypatch):
    snap = _snapshot(ip_exact={"203.0.113.5": "tor_exit_node"})
    _patch_snapshot(monkeypatch, snap)
    email = ParsedEmail(from_address="person@safe.example.com", auth_results=AuthResults(raw_header="spf=pass"))
    assert known_bad_sender.evaluate(email) == []


def test_benign_sender_with_no_auth_header_at_all_stays_clean(monkeypatch):
    snap = _snapshot(ip_exact={"203.0.113.5": "tor_exit_node"})
    _patch_snapshot(monkeypatch, snap)
    email = ParsedEmail(from_address="person@safe.example.com")
    assert known_bad_sender.evaluate(email) == []


def test_disabled_via_settings_flag(monkeypatch):
    monkeypatch.setattr(settings, "enable_threat_intel_indicators", False)
    snap = _snapshot(hostnames={"evil-sender.example": "phishtank"})
    _patch_snapshot(monkeypatch, snap)
    email = ParsedEmail(from_address="attacker@evil-sender.example")
    assert known_bad_sender.evaluate(email) == []
