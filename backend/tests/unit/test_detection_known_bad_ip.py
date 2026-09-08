from __future__ import annotations

from datetime import datetime, timezone

from app.core.config import settings
from app.detections import known_bad_ip
from app.detections.base import ActorEventWindow
from app.events.schema import ActivityEvent, EventAction
from app.threat_intel import loader as threat_intel_loader
from app.threat_intel.loader import ThreatIntelSnapshot

_TS = datetime(2026, 3, 1, 12, 0, tzinfo=timezone.utc)


def _snapshot(**overrides) -> ThreatIntelSnapshot:
    defaults = dict(hostnames={}, urls={}, ip_exact={}, ip_networks=(), snapshot_date="2026-05-01")
    defaults.update(overrides)
    return ThreatIntelSnapshot(**defaults)


def _patch_snapshot(monkeypatch, snap: ThreatIntelSnapshot) -> None:
    monkeypatch.setattr(known_bad_ip, "match_ip", lambda ip: threat_intel_loader.match_ip(ip, snap))


def _event(source_ip: str | None) -> ActivityEvent:
    return ActivityEvent(
        timestamp=_TS, actor="carol@corp.com", action=EventAction.LOGIN,
        outcome="success", source_ip=source_ip,
    )


def test_event_with_matching_source_ip_fires(monkeypatch):
    snap = _snapshot(ip_exact={"203.0.113.5": "tor_exit_node"})
    _patch_snapshot(monkeypatch, snap)
    window = ActorEventWindow(actor="carol@corp.com", events=[_event("203.0.113.5")])
    findings = known_bad_ip.evaluate(window)
    ids = {f.id for f in findings}
    assert "EVENT_IP_KNOWN_MALICIOUS" in ids
    assert "tor_exit_node" in findings[0].description
    assert findings[0].points == 60


def test_clean_ip_does_not_fire(monkeypatch):
    snap = _snapshot(ip_exact={"203.0.113.5": "tor_exit_node"})
    _patch_snapshot(monkeypatch, snap)
    window = ActorEventWindow(actor="carol@corp.com", events=[_event("198.51.100.9")])
    assert known_bad_ip.evaluate(window) == []


def test_event_with_no_source_ip_does_not_fire(monkeypatch):
    snap = _snapshot(ip_exact={"203.0.113.5": "tor_exit_node"})
    _patch_snapshot(monkeypatch, snap)
    window = ActorEventWindow(actor="carol@corp.com", events=[_event(None)])
    assert known_bad_ip.evaluate(window) == []


def test_zero_false_positives_on_benign_actor_control(monkeypatch):
    snap = _snapshot(ip_exact={"203.0.113.5": "tor_exit_node"})
    _patch_snapshot(monkeypatch, snap)
    window = ActorEventWindow(
        actor="dave@corp.com",
        events=[_event("198.51.100.1"), _event("198.51.100.2"), _event("198.51.100.3")],
    )
    assert known_bad_ip.evaluate(window) == []


def test_disabled_via_settings_flag(monkeypatch):
    monkeypatch.setattr(settings, "enable_threat_intel_indicators", False)
    snap = _snapshot(ip_exact={"203.0.113.5": "tor_exit_node"})
    _patch_snapshot(monkeypatch, snap)
    window = ActorEventWindow(actor="carol@corp.com", events=[_event("203.0.113.5")])
    assert known_bad_ip.evaluate(window) == []
