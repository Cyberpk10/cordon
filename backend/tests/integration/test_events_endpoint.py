from __future__ import annotations

from app.db.models import Incident


def test_ingest_attack_batch_creates_incident_with_findings_and_mappings(
    authed_client, db_session, load_events_fixture
):
    events = load_events_fixture("brute_force_attack.json")

    response = authed_client.post("/api/events", json={"events": events})

    assert response.status_code == 200
    body = response.json()
    assert body["accepted"] == len(events)
    assert len(body["incidents_created"]) == 1

    created = body["incidents_created"][0]
    assert created["actor"] == "alice@corp.com"
    assert created["verdict"] in ("suspicious", "malicious")
    assert "BRUTE_FORCE_PASSWORD_SPRAY" in created["detection_types"]

    # Exactly one Incident row persisted — deterministic given the same inputs.
    incidents = db_session.query(Incident).all()
    assert len(incidents) == 1

    detail = authed_client.get(f"/api/incidents/{created['id']}")
    assert detail.status_code == 200
    detail_body = detail.json()
    assert detail_body["findings"][0]["id"] == "BRUTE_FORCE_PASSWORD_SPRAY"
    assert "mitre_attack" in detail_body["framework_mappings"]
    assert len(detail_body["evidence_events"]) >= 5
    assert all(e["action"] == "auth_fail" for e in detail_body["evidence_events"][:5])
    # Backward-compatibility pin (Stage 1 detection hardening): an ordinary single-actor
    # incident's related_actors stays unset.
    assert created["related_actors"] is None
    assert detail_body["related_actors"] is None


def test_ingest_benign_batch_creates_no_incident(authed_client, db_session, load_events_fixture):
    events = load_events_fixture("brute_force_benign.json")

    response = authed_client.post("/api/events", json={"events": events})

    assert response.status_code == 200
    body = response.json()
    assert body["accepted"] == len(events)
    assert body["incidents_created"] == []
    assert db_session.query(Incident).count() == 0


def test_ingesting_events_for_multiple_actors_only_flags_the_non_safe_one(
    authed_client, load_events_fixture
):
    attack_events = load_events_fixture("brute_force_attack.json")
    benign_events = load_events_fixture("off_hours_benign.json")  # different actor, benign

    response = authed_client.post("/api/events", json={"events": attack_events + benign_events})

    assert response.status_code == 200
    body = response.json()
    assert body["accepted"] == len(attack_events) + len(benign_events)
    assert len(body["incidents_created"]) == 1
    assert body["incidents_created"][0]["actor"] == "alice@corp.com"


def test_label_incident_records_analyst_feedback(authed_client, load_events_fixture, test_account):
    events = load_events_fixture("brute_force_attack.json")
    ingest = authed_client.post("/api/events", json={"events": events})
    incident_id = ingest.json()["incidents_created"][0]["id"]

    label_response = authed_client.post(
        f"/api/incidents/{incident_id}/label",
        json={"analyst_verdict": "malicious", "note": "confirmed compromised account"},
    )
    assert label_response.status_code == 200
    label_body = label_response.json()
    assert label_body["incident_id"] == incident_id
    assert label_body["labeled_by"] == test_account.user.email

    detail = authed_client.get(f"/api/incidents/{incident_id}")
    assert detail.json()["latest_label"]["analyst_verdict"] == "malicious"


def test_get_and_delete_incident_lifecycle(authed_client, load_events_fixture):
    events = load_events_fixture("brute_force_attack.json")
    ingest = authed_client.post("/api/events", json={"events": events})
    incident_id = ingest.json()["incidents_created"][0]["id"]

    listing = authed_client.get("/api/incidents")
    assert listing.status_code == 200
    assert any(item["id"] == incident_id for item in listing.json()["items"])

    delete_response = authed_client.delete(f"/api/incidents/{incident_id}")
    assert delete_response.status_code == 204

    missing = authed_client.get(f"/api/incidents/{incident_id}")
    assert missing.status_code == 404


def test_events_with_explicit_utc_offset_timestamps_do_not_crash_across_batches(authed_client):
    """Regression test: ActivityEvent.timestamp accepts ISO8601 both with and without an
    explicit UTC offset (e.g. "+00:00", what datetime.isoformat() produces on an aware
    datetime). Previously, a second /api/events batch for an actor with already-persisted
    events would 500 with "can't compare offset-naive and offset-aware datetimes" — the new
    batch's freshly-parsed events (still holding whatever awareness the client sent) got
    mixed with that actor's DB-loaded history (round-tripped through SQLite, which strips
    tzinfo) inside one detection window, e.g. in app.detections.impossible_travel's sort.
    Reproduced with two logins, geographically far apart, split across two separate POSTs —
    exactly how a real streaming telemetry source would send them."""
    actor = "bob@corp.com"
    first = authed_client.post(
        "/api/events",
        json={
            "events": [
                {
                    "timestamp": "2026-01-06T09:00:00+00:00",
                    "actor": actor,
                    "action": "login",
                    "outcome": "success",
                    "geo": {"country": "US", "region": "NY", "lat": 40.7128, "lon": -74.0060},
                }
            ]
        },
    )
    assert first.status_code == 200

    second = authed_client.post(
        "/api/events",
        json={
            "events": [
                {
                    "timestamp": "2026-01-06T09:30:00+00:00",
                    "actor": actor,
                    "action": "login",
                    "outcome": "success",
                    "geo": {"country": "RU", "region": "Moscow", "lat": 55.7558, "lon": 37.6173},
                }
            ]
        },
    )
    assert second.status_code == 200
    incidents = second.json()["incidents_created"]
    assert len(incidents) == 1
    assert "IMPOSSIBLE_TRAVEL" in incidents[0]["detection_types"]


def test_incidents_are_isolated_per_account(
    authed_client, other_account_authed_client, load_events_fixture
):
    events = load_events_fixture("brute_force_attack.json")
    ingest = authed_client.post("/api/events", json={"events": events})
    incident_id = ingest.json()["incidents_created"][0]["id"]

    listing = other_account_authed_client.get("/api/incidents")
    assert listing.status_code == 200
    assert all(item["id"] != incident_id for item in listing.json()["items"])

    detail = other_account_authed_client.get(f"/api/incidents/{incident_id}")
    assert detail.status_code == 404


# --------------------------------------------------------------------------------------
# Stage 1 detection hardening — cross-actor correlation + cumulative exfiltration.
# --------------------------------------------------------------------------------------


def test_cross_actor_spray_from_one_ip_raises_one_incident(
    authed_client, db_session, load_events_fixture
):
    events = load_events_fixture("cross_actor_spray_attack.json")

    response = authed_client.post("/api/events", json={"events": events})

    assert response.status_code == 200
    body = response.json()
    incidents = body["incidents_created"]
    assert len(incidents) == 1
    assert "CROSS_ACTOR_PASSWORD_SPRAY" in incidents[0]["detection_types"]
    assert len(incidents[0]["related_actors"]) == 15

    # No individual per-actor incidents — exactly one row for the whole spray.
    assert db_session.query(Incident).count() == 1


def test_coordinated_compromise_merges_into_one_incident(
    authed_client, db_session, load_events_fixture
):
    events = load_events_fixture("coordinated_campaign_attack.json")

    response = authed_client.post("/api/events", json={"events": events})

    assert response.status_code == 200
    body = response.json()
    incidents = body["incidents_created"]
    assert len(incidents) == 1

    incident = incidents[0]
    assert sorted(incident["related_actors"]) == [
        "concurrent-1@corp.com",
        "concurrent-2@corp.com",
        "concurrent-3@corp.com",
    ]
    for detection in ("BRUTE_FORCE_PASSWORD_SPRAY", "IMPOSSIBLE_TRAVEL", "DATA_EXFIL_LARGE_TRANSFER", "COORDINATED_ATTACK_CORRELATION"):
        assert detection in incident["detection_types"]

    # Exactly one Incident row — not three.
    assert db_session.query(Incident).count() == 1

    detail = authed_client.get(f"/api/incidents/{incident['id']}")
    assert detail.status_code == 200
    findings = detail.json()["findings"]
    non_correlation = [f for f in findings if f["id"] != "COORDINATED_ATTACK_CORRELATION"]
    assert non_correlation  # sanity: constituent findings were unioned in
    assert all(f["actor"] in incident["related_actors"] for f in non_correlation)


def test_benign_activity_across_shared_ip_stays_safe(
    authed_client, db_session, load_events_fixture
):
    events = load_events_fixture("benign_shared_ip_x3.json")

    response = authed_client.post("/api/events", json={"events": events})

    assert response.status_code == 200
    assert response.json()["incidents_created"] == []
    assert db_session.query(Incident).count() == 0


def test_cumulative_exfil_over_rolling_window_raises_incident(authed_client, db_session):
    actor = "lowslow@corp.com"
    days = [
        "2026-01-06T15:00:00Z",
        "2026-01-07T15:00:00Z",
        "2026-01-08T15:00:00Z",
        "2026-01-09T15:00:00Z",
        "2026-01-12T15:00:00Z",
    ]

    any_incident = False
    for day in days:
        events = [
            {
                "timestamp": day,
                "actor": actor,
                "action": "data_transfer",
                "source_ip": "198.51.100.20",
                "target": "unfamiliar-storage-relay.example.net",
                "bytes": 90_000_000,
                "outcome": "success",
            },
            {
                "timestamp": day,
                "actor": actor,
                "action": "data_transfer",
                "source_ip": "198.51.100.20",
                "target": "unfamiliar-storage-relay.example.net",
                "bytes": 90_000_000,
                "outcome": "success",
            },
        ]
        response = authed_client.post("/api/events", json={"events": events})
        assert response.status_code == 200
        incidents = response.json()["incidents_created"]
        for incident in incidents:
            assert "DATA_EXFIL_LARGE_TRANSFER" not in incident["detection_types"]
            if "CUMULATIVE_EXFIL_VOLUME" in incident["detection_types"]:
                any_incident = True

    assert any_incident
    assert db_session.query(Incident).count() >= 1


def test_spray_incident_is_not_duplicated_by_a_later_unrelated_batch(
    authed_client, db_session, load_events_fixture
):
    """Regression test: Pass 3 (cross-actor spray) deliberately re-scans the whole
    account's auth_fail history every request (so a spray split across many small
    batches isn't missed) — a later, unrelated request that merely contains its own
    auth_fail events must not re-detect the FIRST spray's still-in-window evidence and
    raise a second, duplicate incident for the same 15 accounts."""
    spray_events = load_events_fixture("cross_actor_spray_attack.json")
    first = authed_client.post("/api/events", json={"events": spray_events})
    assert len(first.json()["incidents_created"]) == 1

    # An unrelated actor with a small, sub-threshold auth_fail burst of its own — not a
    # spray by itself, but its presence is what re-triggers Pass 3's account-wide query.
    unrelated_events = [
        {
            "timestamp": "2026-01-06T09:20:00Z",
            "actor": "someone-else@corp.com",
            "action": "auth_fail",
            "source_ip": "203.0.113.99",
            "outcome": "failure",
        }
    ]
    second = authed_client.post("/api/events", json={"events": unrelated_events})
    assert second.json()["incidents_created"] == []

    spray_incidents = [
        i for i in db_session.query(Incident).all() if i.detection_types == ["CROSS_ACTOR_PASSWORD_SPRAY"]
    ]
    assert len(spray_incidents) == 1
