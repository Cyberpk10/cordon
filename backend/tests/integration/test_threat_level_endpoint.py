from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.db.models import ActorThreatLevel, Incident


def _entry(body: dict, actor: str) -> dict | None:
    return next((a for a in body["actors"] if a["actor"] == actor), None)


def test_chain_forming_progression_reaches_elevated_before_any_incident(authed_client, db_session):
    """The flagship test: the exact numerically-verified auth -> sensitive-access ->
    transfer progression (see the Stage 1 plan/test_threat_level_aggregation) reaches
    ELEVATED by day 8 through the real POST /api/events -> GET /api/threat-level path,
    while GET /api/incidents confirms no incident ever formed for this actor — each event
    is, by construction, one of Stage D's sub-floor weak categories."""
    actor = "chain-actor@corp.com"
    # Anchored to real wall-clock "now" (not a fixed historical date): GET /api/threat-level
    # decays-on-read against the REAL clock (app/api/routes/threat_level.py), unlike Stage
    # D's chronic score, which is only ever read back inside the SAME POST /api/events
    # response that computed it. day8 lands at ~now, so the read right after adds only
    # seconds of extra decay, not months.
    t0 = datetime.now(timezone.utc) - timedelta(days=8)

    day0 = [
        {"timestamp": t0.isoformat(), "actor": actor, "action": "auth_fail", "outcome": "failure"}
        for _ in range(2)
    ]
    day5_ts = t0 + timedelta(days=5)
    day5 = [
        {
            "timestamp": day5_ts.isoformat(), "actor": actor, "action": "file_access",
            "target": "finance/report.xlsx", "outcome": "success",
        }
    ]
    day8_ts = t0 + timedelta(days=8)
    day8 = [
        {
            "timestamp": day8_ts.isoformat(), "actor": actor, "action": "data_transfer",
            "target": "unfamiliar-host.example.net", "bytes": 10_000_000, "outcome": "success",
        }
    ]

    for batch in (day0, day5, day8):
        resp = authed_client.post("/api/events", json={"events": batch})
        assert resp.status_code == 200
        assert resp.json()["incidents_created"] == []  # no incident at any point

    tl = authed_client.get("/api/threat-level")
    assert tl.status_code == 200
    entry = _entry(tl.json(), actor)
    assert entry is not None
    assert entry["level"] == "elevated"
    assert round(entry["score"], 1) == 35.3

    signal_types = {s["type"] for s in entry["contributing_signals"]}
    assert signal_types == {"AUTH_ANOMALY", "FIRST_TIME_SENSITIVE_ACCESS", "SMALL_UNFAMILIAR_TRANSFER"}

    incidents = db_session.query(Incident).filter(Incident.actor == actor).all()
    assert incidents == []


def test_benign_actor_with_one_isolated_signal_stays_low(authed_client):
    actor = "isolated-signal@corp.com"
    t0 = datetime(2026, 6, 1, 14, 0, tzinfo=timezone.utc)
    events = [
        {"timestamp": t0.isoformat(), "actor": actor, "action": "auth_fail", "outcome": "failure"}
    ]
    resp = authed_client.post("/api/events", json={"events": events})
    assert resp.status_code == 200
    assert resp.json()["incidents_created"] == []

    tl = authed_client.get("/api/threat-level")
    entry = _entry(tl.json(), actor)
    assert entry is not None
    assert entry["level"] == "low"


def test_decay_reduces_score_on_a_later_read(authed_client, db_session, test_account):
    actor = "decay-check@corp.com"
    t0 = datetime(2026, 6, 1, 14, 0, tzinfo=timezone.utc)
    events = [
        {"timestamp": t0.isoformat(), "actor": actor, "action": "auth_fail", "outcome": "failure"}
        for _ in range(2)
    ]
    resp = authed_client.post("/api/events", json={"events": events})
    assert resp.status_code == 200

    row = (
        db_session.query(ActorThreatLevel)
        .filter(ActorThreatLevel.account_id == test_account.account.id, ActorThreatLevel.actor == actor)
        .first()
    )
    raw_score = row.current_score
    assert raw_score > 0

    # Push last_updated back 14 days (one configured half-life) with no new activity —
    # decay-on-read (app.api.routes.threat_level) must reflect roughly half the score.
    row.last_updated = row.last_updated.replace(year=row.last_updated.year) - timedelta(days=14)
    db_session.commit()

    tl = authed_client.get("/api/threat-level")
    entry = _entry(tl.json(), actor)
    assert entry is not None
    assert entry["score"] < raw_score * 0.6


def test_benign_multi_week_control_never_leaves_low(authed_client):
    """Zero-false-positive control: occasional, well-spaced, single-category weak signals
    over months — never co-occurring, so nothing crosses into elevated at any point."""
    actor = "benign-watchlist@corp.com"
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

        tl = authed_client.get("/api/threat-level")
        entry = _entry(tl.json(), actor)
        if entry is not None:
            assert entry["level"] == "low"
