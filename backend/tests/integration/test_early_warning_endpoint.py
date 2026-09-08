from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.db.models import AuditLogEntry, Incident


def test_forming_chain_raises_early_warning_before_any_incident(authed_client, db_session):
    """The flagship test: replays the exact numerically-verified auth -> sensitive-access ->
    transfer progression (see app.threat_level's own Stage 1 tests) through POST
    /api/events. GET /api/early-warnings must show an active "attack forming" alert with the
    correct ordered signal timeline BEFORE GET /api/incidents shows anything for this actor —
    each event is, by construction, one of Stage D's sub-floor weak categories that never
    trips a real detector on its own."""
    actor = "chain-actor@corp.com"
    # Anchored to real wall-clock "now", same reasoning as Stage 1's own integration test:
    # GET /api/early-warnings computes has_active_incident/band fresh on read.
    t0 = datetime.now(timezone.utc) - timedelta(days=8)

    day0 = [
        {"timestamp": t0.isoformat(), "actor": actor, "action": "auth_fail", "outcome": "failure"}
        for _ in range(2)
    ]
    day5 = [
        {
            "timestamp": (t0 + timedelta(days=5)).isoformat(), "actor": actor, "action": "file_access",
            "target": "finance/report.xlsx", "outcome": "success",
        }
    ]
    day8 = [
        {
            "timestamp": (t0 + timedelta(days=8)).isoformat(), "actor": actor, "action": "data_transfer",
            "target": "unfamiliar-host.example.net", "bytes": 10_000_000, "outcome": "success",
        }
    ]

    for batch in (day0, day5, day8):
        resp = authed_client.post("/api/events", json={"events": batch})
        assert resp.status_code == 200
        assert resp.json()["incidents_created"] == []

    ew = authed_client.get("/api/early-warnings")
    assert ew.status_code == 200
    alerts = ew.json()["alerts"]
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["actor"] == actor
    assert alert["band"] == "attack_forming"

    signal_types_in_order = [s["type"] for s in alert["signal_timeline"]]
    assert signal_types_in_order == ["AUTH_ANOMALY", "FIRST_TIME_SENSITIVE_ACCESS", "SMALL_UNFAMILIAR_TRANSFER"]
    assert "AUTH_ANOMALY" in alert["timeline_summary"] or "failed logins" in alert["timeline_summary"]
    assert alert["recommended_actions"]  # at least one recommended step
    assert "mitre_attack" in alert["framework_mappings"]

    incidents = db_session.query(Incident).filter(Incident.actor == actor).all()
    assert incidents == []


def test_benign_multi_week_control_never_raises_an_alert(authed_client):
    """Zero-false-positive control: reuses Stage 1's own benign multi-week shape (occasional,
    well-spaced, single-category weak signals — never co-occurring)."""
    actor = "benign-watchlist-ew@corp.com"
    t0 = datetime(2026, 6, 1, 14, 0, tzinfo=timezone.utc)

    for week in range(12):
        day = t0 + timedelta(weeks=week)
        if week % 4 == 0:
            events = [
                {"timestamp": day.isoformat(), "actor": actor, "action": "auth_fail", "outcome": "failure"}
            ]
        elif week % 6 == 0:
            events = [
                {
                    "timestamp": day.isoformat(), "actor": actor, "action": "data_transfer",
                    "target": "occasional-partner.example.net", "bytes": 8_000_000, "outcome": "success",
                }
            ]
        else:
            events = [{"timestamp": day.isoformat(), "actor": actor, "action": "login", "outcome": "success"}]

        resp = authed_client.post("/api/events", json={"events": events})
        assert resp.status_code == 200
        assert resp.json()["incidents_created"] == []

    ew = authed_client.get("/api/early-warnings")
    assert ew.status_code == 200
    assert all(a["actor"] != actor for a in ew.json()["alerts"])


def test_ack_removes_alert_from_active_list_and_writes_audit_log(authed_client, db_session):
    """Same numerically-verified 3-signal progression as the flagship test — guarantees a
    real crossing into attack_forming rather than inventing a new, unverified cadence."""
    actor = "ack-actor@corp.com"
    t0 = datetime.now(timezone.utc) - timedelta(days=8)

    day0 = [
        {"timestamp": t0.isoformat(), "actor": actor, "action": "auth_fail", "outcome": "failure"}
        for _ in range(2)
    ]
    day5 = [
        {
            "timestamp": (t0 + timedelta(days=5)).isoformat(), "actor": actor, "action": "file_access",
            "target": "finance/report.xlsx", "outcome": "success",
        }
    ]
    day8 = [
        {
            "timestamp": (t0 + timedelta(days=8)).isoformat(), "actor": actor, "action": "data_transfer",
            "target": "unfamiliar-host.example.net", "bytes": 10_000_000, "outcome": "success",
        }
    ]
    for batch in (day0, day5, day8):
        resp = authed_client.post("/api/events", json={"events": batch})
        assert resp.status_code == 200

    ew = authed_client.get("/api/early-warnings")
    alerts = [a for a in ew.json()["alerts"] if a["actor"] == actor]
    assert len(alerts) == 1
    alert_id = alerts[0]["id"]

    ack = authed_client.post(f"/api/early-warnings/{alert_id}/ack")
    assert ack.status_code == 200
    assert ack.json()["actor"] == actor

    ew_after = authed_client.get("/api/early-warnings")
    assert all(a["actor"] != actor for a in ew_after.json()["alerts"])

    audit_rows = (
        db_session.query(AuditLogEntry)
        .filter(AuditLogEntry.event_type == "early_warning_acknowledged")
        .all()
    )
    assert any(row.detail.get("alert_id") == alert_id for row in audit_rows)
