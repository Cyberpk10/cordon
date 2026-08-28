"""Required test: the landing page must record click/submit EVENTS only, and it must be a
schema-level impossibility — not just an application-level omission — for a submitted
credential to ever be persisted anywhere in this code path.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import text

from app.core.config import settings
from app.db.models import SimulationDomain, SimulationEvent, SimulationRecipient


def _verify_domain(db_session, account_id, domain: str) -> None:
    db_session.add(
        SimulationDomain(
            account_id=account_id,
            domain=domain,
            verification_token="test-token",
            status="verified",
            verified_at=datetime.now(timezone.utc),
        )
    )
    db_session.commit()


def _create_and_send_dry_run_campaign(authed_client, db_session, test_account, monkeypatch) -> str:
    monkeypatch.setattr(settings, "enable_phishing_simulation", True)
    _verify_domain(db_session, test_account.account.id, "corp.example.com")
    created = authed_client.post(
        "/api/sim/campaigns",
        json={
            "name": "Track test",
            "template_id": "it_password_reset",
            "recipients": [{"email": "alice@corp.example.com"}],
        },
    ).json()
    sent = authed_client.post(
        f"/api/sim/campaigns/{created['id']}/send", json={"authorization_accepted": True}
    ).json()
    tracking_url = sent["recipients"][0]["dry_run_tracking_url"]
    token = tracking_url.rsplit("/track/", 1)[1]
    return token


def test_unknown_token_returns_404_html_and_creates_no_rows(client, db_session):
    response = client.get("/api/sim/track/not-a-real-token")

    assert response.status_code == 404
    assert "text/html" in response.headers["content-type"]
    assert db_session.query(SimulationEvent).count() == 0


def test_click_records_event_and_promotes_status(authed_client, db_session, test_account, monkeypatch, client):
    token = _create_and_send_dry_run_campaign(authed_client, db_session, test_account, monkeypatch)

    response = client.get(f"/api/sim/track/{token}")

    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "phishing simulation" in response.text.lower()

    recipient = db_session.query(SimulationRecipient).one()
    assert recipient.status == "clicked"
    assert recipient.click_count == 1
    assert recipient.clicked_at is not None

    events = db_session.query(SimulationEvent).all()
    assert len(events) == 1
    assert events[0].event_type == "click"


def test_submit_is_recorded_as_a_second_distinct_event(
    authed_client, db_session, test_account, monkeypatch, client
):
    token = _create_and_send_dry_run_campaign(authed_client, db_session, test_account, monkeypatch)

    client.get(f"/api/sim/track/{token}")
    response = client.get(f"/api/sim/track/{token}", params={"event": "submit"})

    assert response.status_code == 200

    recipient = db_session.query(SimulationRecipient).one()
    assert recipient.status == "submitted"
    assert recipient.submit_count == 1
    assert recipient.submitted_at is not None

    events = db_session.query(SimulationEvent).order_by(SimulationEvent.occurred_at).all()
    assert [e.event_type for e in events] == ["click", "submit"]


def test_repeated_clicks_increment_count_without_regressing_status(
    authed_client, db_session, test_account, monkeypatch, client
):
    token = _create_and_send_dry_run_campaign(authed_client, db_session, test_account, monkeypatch)

    client.get(f"/api/sim/track/{token}", params={"event": "submit"})
    client.get(f"/api/sim/track/{token}")  # a click after already submitting

    recipient = db_session.query(SimulationRecipient).one()
    assert recipient.status == "submitted"  # never regresses
    assert recipient.click_count == 1


def test_submitting_an_arbitrary_credential_payload_leaves_no_trace_in_the_database(
    authed_client, db_session, test_account, monkeypatch, client
):
    """The fake login form never transmits what was typed — proven here by attaching an
    attacker-shaped payload directly to the request and confirming it never reaches
    storage, since the route itself never reads a request body at all."""
    token = _create_and_send_dry_run_campaign(authed_client, db_session, test_account, monkeypatch)

    response = client.request(
        "GET",
        f"/api/sim/track/{token}",
        params={"event": "submit"},
        json={"username": "alice", "password": "hunter2"},
    )
    assert response.status_code == 200

    recipient = db_session.query(SimulationRecipient).one()
    assert recipient.status == "submitted"

    # Sweep every column on every row of both tables for any trace of the submitted value.
    for row in db_session.query(SimulationRecipient).all():
        for column in SimulationRecipient.__table__.columns:
            assert "hunter2" not in str(getattr(row, column.name) or "")
    for row in db_session.query(SimulationEvent).all():
        for column in SimulationEvent.__table__.columns:
            assert "hunter2" not in str(getattr(row, column.name) or "")


def test_simulation_recipients_table_has_no_credential_shaped_column(db_session):
    columns = {
        row[1]
        for row in db_session.execute(text("PRAGMA table_info(simulation_recipients)")).fetchall()
    }
    known_safe = {
        "id",
        "account_id",
        "campaign_id",
        "email",
        "token_hash",
        "status",
        "sent_at",
        "send_error",
        "mailgun_message_id",
        "clicked_at",
        "click_count",
        "submitted_at",
        "submit_count",
        "department",
        "reported_at",
        "report_count",
        "created_at",
    }
    assert columns == known_safe


def test_simulation_events_table_has_no_credential_shaped_column(db_session):
    columns = {
        row[1] for row in db_session.execute(text("PRAGMA table_info(simulation_events)")).fetchall()
    }
    known_safe = {
        "id",
        "account_id",
        "campaign_id",
        "recipient_id",
        "event_type",
        "occurred_at",
        "ip_address",
    }
    assert columns == known_safe


def test_click_on_a_template_with_fake_form_renders_form_html(
    authed_client, db_session, test_account, monkeypatch, client
):
    token = _create_and_send_dry_run_campaign(authed_client, db_session, test_account, monkeypatch)
    response = client.get(f"/api/sim/track/{token}")
    assert "<form" in response.text


def test_track_endpoint_requires_no_authentication(client, authed_client, db_session, test_account, monkeypatch):
    """Confirms the public landing-page route is reachable with zero credentials — by
    design, since the person clicking is an anonymous trainee, not a logged-in Cordon user."""
    token = _create_and_send_dry_run_campaign(authed_client, db_session, test_account, monkeypatch)
    assert "Authorization" not in client.headers
    response = client.get(f"/api/sim/track/{token}")
    assert response.status_code == 200
