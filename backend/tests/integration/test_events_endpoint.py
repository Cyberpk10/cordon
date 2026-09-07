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


# --------------------------------------------------------------------------------------
# Detection max-out Stage B — behavioral baselines with anti-poisoning.
# --------------------------------------------------------------------------------------

from datetime import datetime, timedelta, timezone  # noqa: E402


def _business_days(start: datetime, count: int) -> list[datetime]:
    days: list[datetime] = []
    current = start
    while len(days) < count:
        if current.weekday() < 5:
            days.append(current)
        current += timedelta(days=1)
    return days


def test_insider_first_time_sensitive_sweep_raises_incident(authed_client, db_session):
    """Replays phase 2 scenario 4's exact shape end-to-end: 6 days of honest baseline
    activity via the real ingestion path, then one attack day touching finance/HR/legal for
    the first time at completely normal volume and hours."""
    actor = "insider@corp.com"
    t0 = datetime(2026, 1, 6, 15, 0, tzinfo=timezone.utc)
    baseline_days = _business_days(t0, 6)
    normal_targets = [
        "shared/team-project/roadmap.docx",
        "shared/team-project/notes.docx",
        "shared/team-project/status-update.pptx",
        "shared/team-project/budget-draft.xlsx",
    ]

    for day in baseline_days:
        events = [
            {
                "timestamp": day.replace(hour=15, minute=0).isoformat(),
                "actor": actor,
                "action": "login",
                "outcome": "success",
                "geo": {"country": "US", "region": "NY", "lat": 40.7128, "lon": -74.0060},
            }
        ]
        for i in range(4):
            events.append(
                {
                    "timestamp": day.replace(hour=15, minute=5 + i * 3).isoformat(),
                    "actor": actor,
                    "action": "file_access",
                    "target": normal_targets[i % len(normal_targets)],
                    "outcome": "success",
                }
            )
        response = authed_client.post("/api/events", json={"events": events})
        assert response.status_code == 200
        assert response.json()["incidents_created"] == []

    attack_day = _business_days(baseline_days[-1] + timedelta(days=1), 1)[0]
    attack_events = [
        {
            "timestamp": attack_day.replace(hour=15, minute=0).isoformat(),
            "actor": actor,
            "action": "login",
            "outcome": "success",
            "geo": {"country": "US", "region": "NY", "lat": 40.7128, "lon": -74.0060},
        }
    ]
    sensitive_targets = [
        "finance/q3-budget-actuals.xlsx",
        "finance/payroll-adjustments.xlsx",
        "hr/comp-review-2026.xlsx",
        "hr/pending-terminations.docx",
        "legal/pending-litigation-notes.docx",
    ]
    for i, target in enumerate(sensitive_targets):
        attack_events.append(
            {
                "timestamp": attack_day.replace(hour=15, minute=5 + i * 3).isoformat(),
                "actor": actor,
                "action": "file_access",
                "target": target,
                "outcome": "success",
            }
        )

    response = authed_client.post("/api/events", json={"events": attack_events})
    assert response.status_code == 200
    incidents = response.json()["incidents_created"]
    assert len(incidents) == 1
    assert "SENSITIVE_RESOURCE_FIRST_ACCESS" in incidents[0]["detection_types"]
    assert incidents[0]["verdict"] != "safe"


def test_gradual_poisoning_ramp_raises_incident_end_to_end(authed_client, db_session):
    """Replays the numerically-verified phase 3/4 ramp end-to-end through POST /api/events,
    confirming no single day's batch individually crosses the per-day volume-spike check
    (matching the scripts' own dim() output showing 'safe, as expected' throughout the ramp)
    while the ramp itself is still caught by the account-wide baseline afterward."""
    actor = "tradecraft@corp.com"
    t0 = datetime(2026, 1, 5, 15, 0, tzinfo=timezone.utc)
    days = _business_days(t0, 20)
    normal_targets = [f"shared/team-project/doc-{i}.docx" for i in range(5)]
    sensitive_targets = [
        "finance/q3-budget-actuals.xlsx",
        "finance/payroll-adjustments.xlsx",
        "hr/comp-review-2026.xlsx",
        "hr/pending-terminations.docx",
        "legal/pending-litigation-notes.docx",
    ]
    ramp = [4, 4, 5, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 12, 13, 14]

    any_incident = False
    for day_index, (day, count) in enumerate(zip(days, ramp)):
        n_sensitive = min(len(sensitive_targets), day_index // 4)
        n_normal = len(normal_targets) - n_sensitive
        pool = normal_targets[:n_normal] + sensitive_targets[:n_sensitive]
        events = [
            {
                "timestamp": day.replace(hour=15, minute=5 + i * 2).isoformat(),
                "actor": actor,
                "action": "file_access",
                "target": pool[i % len(pool)],
                "outcome": "success",
            }
            for i in range(count)
        ]
        response = authed_client.post("/api/events", json={"events": events})
        assert response.status_code == 200
        if response.json()["incidents_created"]:
            any_incident = True

    assert any_incident

    ramp_incidents = [
        i for i in db_session.query(Incident).all() if "BASELINE_RAMP_ANOMALY" in i.detection_types
    ]
    assert len(ramp_incidents) >= 1


def test_benign_organic_growth_stays_safe_across_the_whole_ramp(authed_client):
    """The zero-false-positive control: an actor whose raw volume organically grows over
    weeks while their sensitive-access share stays flat must never raise an incident."""
    actor = "growing-role@corp.com"
    t0 = datetime(2026, 1, 5, 15, 0, tzinfo=timezone.utc)
    days = _business_days(t0, 20)
    counts = [4, 4, 4, 5, 4, 5, 5, 5, 6, 5, 6, 6, 7, 6, 7, 7, 7, 8, 8, 8]

    for day, count in zip(days, counts):
        n_sensitive = round(count * 0.2)
        events = []
        for i in range(count):
            target = "finance/report.xlsx" if i < n_sensitive else "shared/notes.docx"
            events.append(
                {
                    "timestamp": day.replace(hour=15, minute=5 + i * 2).isoformat(),
                    "actor": actor,
                    "action": "file_access",
                    "target": target,
                    "outcome": "success",
                }
            )
        response = authed_client.post("/api/events", json={"events": events})
        assert response.status_code == 200
        assert response.json()["incidents_created"] == []


# --------------------------------------------------------------------------------------
# Detection max-out Stage C — multi-window cumulative exfiltration.
# --------------------------------------------------------------------------------------


def _weekday_snap_exfil(dt: datetime) -> datetime:
    while dt.weekday() >= 5:
        dt += timedelta(days=1)
    return dt


def test_medium_window_catches_phase3_scenario2_cadence_end_to_end(authed_client, db_session):
    """Replays phase 3 #2's exact cadence (280MB every 12 days) through POST /api/events —
    no single batch ever contains 2 transfers, so the endpoint's own short-window path never
    fires, but the medium (30-day) tier does once enough cycles accumulate."""
    actor = "windowspread@corp.com"
    t0 = datetime(2026, 6, 1, 15, 0, tzinfo=timezone.utc)
    any_incident = False

    for cycle in range(7):
        day = _weekday_snap_exfil(t0 + timedelta(days=12 * cycle))
        events = [
            {
                "timestamp": day.isoformat(),
                "actor": actor,
                "action": "data_transfer",
                "target": f"unfamiliar-host-{cycle % 2}.example.net",
                "bytes": 280_000_000,
                "outcome": "success",
            }
        ]
        response = authed_client.post("/api/events", json={"events": events})
        assert response.status_code == 200
        if response.json()["incidents_created"]:
            any_incident = True

    assert any_incident
    incidents = [
        i for i in db_session.query(Incident).all() if "CUMULATIVE_EXFIL_VOLUME" in i.detection_types
    ]
    assert len(incidents) >= 1


def test_long_window_catches_phase4_scenario4_cadence_end_to_end(authed_client, db_session):
    """Replays phase 4 #4's exact cadence (150MB every 12 days across 4 destinations) — the
    medium tier never fires for this quieter cadence, but the long (90-day) tier does."""
    actor = "distributed@corp.com"
    t0 = datetime(2026, 6, 1, 15, 0, tzinfo=timezone.utc)
    hosts = [
        "unfamiliar-cdn-node.example.net",
        "partner-backup-relay.example.net",
        "unfamiliar-storage-relay.example.net",
        "edge-cache-mirror.example.net",
    ]
    any_incident = False

    for cycle in range(9):
        day = _weekday_snap_exfil(t0 + timedelta(days=12 * cycle))
        events = [
            {
                "timestamp": day.isoformat(),
                "actor": actor,
                "action": "data_transfer",
                "target": hosts[cycle % len(hosts)],
                "bytes": 150_000_000,
                "outcome": "success",
            }
        ]
        response = authed_client.post("/api/events", json={"events": events})
        assert response.status_code == 200
        if response.json()["incidents_created"]:
            any_incident = True

    assert any_incident


def test_benign_multi_month_low_volume_transfers_stay_safe(authed_client):
    """Zero-false-positive control: modest, spread-out non-allowlisted transfers over
    months, staying under every tier's threshold."""
    actor = "routine-vendor-sync@corp.com"
    t0 = datetime(2026, 6, 1, 15, 0, tzinfo=timezone.utc)

    for i in range(5):
        day = _weekday_snap_exfil(t0 + timedelta(days=18 * i))
        events = [
            {
                "timestamp": day.isoformat(),
                "actor": actor,
                "action": "data_transfer",
                "target": f"partner-{i}.example.net",
                "bytes": 80_000_000,
                "outcome": "success",
            }
        ]
        response = authed_client.post("/api/events", json={"events": events})
        assert response.status_code == 200
        assert response.json()["incidents_created"] == []
