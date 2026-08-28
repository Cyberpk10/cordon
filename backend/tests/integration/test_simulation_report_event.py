"""M9 Stage 2 — the "report this email" signal must be independent of the click/submit
status ratchet: reporting is a good outcome and must never advance or regress `status`.
"""

from __future__ import annotations

from datetime import datetime, timezone

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
            "name": "Report test",
            "template_id": "it_password_reset",
            "recipients": [{"email": "alice@corp.example.com"}],
        },
    ).json()
    sent = authed_client.post(
        f"/api/sim/campaigns/{created['id']}/send", json={"authorization_accepted": True}
    ).json()
    tracking_url = sent["recipients"][0]["dry_run_tracking_url"]
    return tracking_url.rsplit("/track/", 1)[1]


def test_report_sets_reported_at_and_report_count(authed_client, db_session, test_account, monkeypatch, client):
    token = _create_and_send_dry_run_campaign(authed_client, db_session, test_account, monkeypatch)

    response = client.get(f"/api/sim/track/{token}", params={"event": "report"})

    assert response.status_code == 200
    assert "great catch" in response.text.lower()

    recipient = db_session.query(SimulationRecipient).one()
    assert recipient.reported_at is not None
    assert recipient.report_count == 1
    assert recipient.status == "sent"  # untouched by a report — Stage 1 already set "sent" at send time


def test_report_writes_a_distinct_event_type(authed_client, db_session, test_account, monkeypatch, client):
    token = _create_and_send_dry_run_campaign(authed_client, db_session, test_account, monkeypatch)
    client.get(f"/api/sim/track/{token}", params={"event": "report"})

    events = db_session.query(SimulationEvent).all()
    assert len(events) == 1
    assert events[0].event_type == "report"


def test_report_before_a_click_does_not_prevent_the_click_from_being_recorded(
    authed_client, db_session, test_account, monkeypatch, client
):
    token = _create_and_send_dry_run_campaign(authed_client, db_session, test_account, monkeypatch)
    client.get(f"/api/sim/track/{token}", params={"event": "report"})
    client.get(f"/api/sim/track/{token}")  # plain click afterward

    recipient = db_session.query(SimulationRecipient).one()
    assert recipient.reported_at is not None
    assert recipient.status == "clicked"

    event_types = sorted(e.event_type for e in db_session.query(SimulationEvent).all())
    assert event_types == ["click", "report"]


def test_click_then_report_leaves_status_as_clicked_not_regressed_or_advanced(
    authed_client, db_session, test_account, monkeypatch, client
):
    token = _create_and_send_dry_run_campaign(authed_client, db_session, test_account, monkeypatch)
    client.get(f"/api/sim/track/{token}")  # click
    client.get(f"/api/sim/track/{token}", params={"event": "report"})  # then report

    recipient = db_session.query(SimulationRecipient).one()
    assert recipient.status == "clicked"
    assert recipient.reported_at is not None


def test_report_never_creates_a_training_recommendation_on_its_own(
    authed_client, db_session, test_account, monkeypatch, client
):
    from app.db.models import SimulationTrainingRecommendation

    token = _create_and_send_dry_run_campaign(authed_client, db_session, test_account, monkeypatch)
    client.get(f"/api/sim/track/{token}", params={"event": "report"})

    assert db_session.query(SimulationTrainingRecommendation).count() == 0
