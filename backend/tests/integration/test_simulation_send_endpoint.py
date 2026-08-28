from __future__ import annotations

from datetime import datetime, timezone

import httpx
import respx

from app.core.config import settings
from app.db.models import AuditLogEntry, SimulationDomain


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


def _create_campaign(authed_client, db_session, test_account, *, email="alice@corp.example.com") -> str:
    _verify_domain(db_session, test_account.account.id, "corp.example.com")
    response = authed_client.post(
        "/api/sim/campaigns",
        json={
            "name": "Q1 awareness test",
            "template_id": "it_password_reset",
            "recipients": [{"email": email}],
        },
    )
    assert response.status_code == 201
    return response.json()["id"]


def test_send_without_authorization_field_is_rejected(authed_client, db_session, test_account, monkeypatch):
    monkeypatch.setattr(settings, "enable_phishing_simulation", True)
    campaign_id = _create_campaign(authed_client, db_session, test_account)

    response = authed_client.post(f"/api/sim/campaigns/{campaign_id}/send", json={})

    assert response.status_code == 422
    assert authed_client.get(f"/api/sim/campaigns/{campaign_id}").json()["status"] == "draft"


def test_send_with_authorization_false_is_rejected(authed_client, db_session, test_account, monkeypatch):
    monkeypatch.setattr(settings, "enable_phishing_simulation", True)
    campaign_id = _create_campaign(authed_client, db_session, test_account)

    response = authed_client.post(
        f"/api/sim/campaigns/{campaign_id}/send", json={"authorization_accepted": False}
    )

    assert response.status_code == 400
    assert authed_client.get(f"/api/sim/campaigns/{campaign_id}").json()["status"] == "draft"


def test_send_rejected_when_feature_flag_is_off(authed_client, db_session, test_account, monkeypatch):
    monkeypatch.setattr(settings, "enable_phishing_simulation", False)
    campaign_id = _create_campaign(authed_client, db_session, test_account)

    response = authed_client.post(
        f"/api/sim/campaigns/{campaign_id}/send", json={"authorization_accepted": True}
    )

    assert response.status_code == 503


def test_sending_the_same_campaign_twice_conflicts(authed_client, db_session, test_account, monkeypatch):
    monkeypatch.setattr(settings, "enable_phishing_simulation", True)
    campaign_id = _create_campaign(authed_client, db_session, test_account)

    first = authed_client.post(
        f"/api/sim/campaigns/{campaign_id}/send", json={"authorization_accepted": True}
    )
    assert first.status_code == 200

    second = authed_client.post(
        f"/api/sim/campaigns/{campaign_id}/send", json={"authorization_accepted": True}
    )
    assert second.status_code == 409


def test_non_admin_cannot_send(analyst_authed_client, authed_client, db_session, test_account, monkeypatch):
    monkeypatch.setattr(settings, "enable_phishing_simulation", True)
    campaign_id = _create_campaign(authed_client, db_session, test_account)

    response = analyst_authed_client.post(
        f"/api/sim/campaigns/{campaign_id}/send", json={"authorization_accepted": True}
    )
    assert response.status_code == 403


def test_dry_run_send_marks_sent_and_logs_authorization_and_send_events(
    authed_client, db_session, test_account, monkeypatch
):
    """Mailgun is unconfigured by default in the test suite (see tests/conftest.py's
    offline-by-default fixtures) — this exercises the dry-run fallback end to end."""
    monkeypatch.setattr(settings, "enable_phishing_simulation", True)
    campaign_id = _create_campaign(authed_client, db_session, test_account)

    response = authed_client.post(
        f"/api/sim/campaigns/{campaign_id}/send", json={"authorization_accepted": True}
    )

    assert response.status_code == 200
    body = response.json()
    assert body["dry_run"] is True
    assert body["status"] == "sent"
    assert body["authorized_by_user_id"] == str(test_account.user.id)
    assert body["authorized_at"] is not None
    assert body["recipients"][0]["status"] == "sent"
    assert body["recipients"][0]["dry_run_tracking_url"] is not None
    assert "/api/sim/track/" in body["recipients"][0]["dry_run_tracking_url"]

    event_types = {
        row.event_type
        for row in db_session.query(AuditLogEntry).filter(
            AuditLogEntry.account_id == test_account.account.id
        )
    }
    assert "simulation_campaign_authorized" in event_types
    assert "simulation_campaign_sent" in event_types


def test_get_campaign_after_send_does_not_expose_the_tracking_url_again(
    authed_client, db_session, test_account, monkeypatch
):
    """dry_run_tracking_url is only ever returned in the direct /send response — the raw
    token is never persisted, so a later GET cannot and must not reconstruct it."""
    monkeypatch.setattr(settings, "enable_phishing_simulation", True)
    campaign_id = _create_campaign(authed_client, db_session, test_account)
    authed_client.post(f"/api/sim/campaigns/{campaign_id}/send", json={"authorization_accepted": True})

    response = authed_client.get(f"/api/sim/campaigns/{campaign_id}")
    assert response.json()["recipients"][0]["dry_run_tracking_url"] is None


def test_real_send_with_partial_mailgun_failure_records_mixed_statuses(
    authed_client, db_session, test_account, monkeypatch
):
    monkeypatch.setattr(settings, "enable_phishing_simulation", True)
    monkeypatch.setattr(settings, "mailgun_api_key", "test-key")
    monkeypatch.setattr(settings, "simulation_sending_domain", "sim.cordon.example")
    monkeypatch.setattr(settings, "simulation_tracking_base_url", "https://track.cordon.example")

    _verify_domain(db_session, test_account.account.id, "corp.example.com")
    created = authed_client.post(
        "/api/sim/campaigns",
        json={
            "name": "Partial failure",
            "template_id": "it_password_reset",
            "recipients": [
                {"email": "alice@corp.example.com"},
                {"email": "bob@corp.example.com"},
            ],
        },
    ).json()

    send_url = f"{settings.mailgun_api_base_url}/{settings.simulation_sending_domain}/messages"
    with respx.mock() as mock:
        mock.post(send_url).mock(
            side_effect=[
                httpx.Response(200, json={"id": "<msg-1>"}),
                httpx.Response(500, text="mailgun error"),
            ]
        )
        response = authed_client.post(
            f"/api/sim/campaigns/{created['id']}/send", json={"authorization_accepted": True}
        )

    assert response.status_code == 200
    body = response.json()
    assert body["dry_run"] is False
    assert body["status"] == "sent"  # at least one succeeded
    statuses = [r["status"] for r in body["recipients"]]
    assert statuses.count("sent") == 1
    assert statuses.count("send_failed") == 1
    for recipient in body["recipients"]:
        assert recipient["dry_run_tracking_url"] is None
