from __future__ import annotations

from datetime import datetime, timezone

from app.core.config import settings
from app.db.models import SimulationDomain


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


def test_recommendations_list_reflects_stored_rows(authed_client, db_session, test_account, monkeypatch, client):
    monkeypatch.setattr(settings, "enable_phishing_simulation", True)
    _verify_domain(db_session, test_account.account.id, "corp.example.com")
    created = authed_client.post(
        "/api/sim/campaigns",
        json={
            "name": "Rec test",
            "template_id": "it_password_reset",
            "recipients": [{"email": "alice@corp.example.com"}],
        },
    ).json()
    sent = authed_client.post(
        f"/api/sim/campaigns/{created['id']}/send", json={"authorization_accepted": True}
    ).json()
    token = sent["recipients"][0]["dry_run_tracking_url"].rsplit("/track/", 1)[1]
    client.get(f"/api/sim/track/{token}")

    response = authed_client.get("/api/human-risk/recommendations")
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    assert body["items"][0]["recipient"] == "alice@corp.example.com"
    assert body["items"][0]["template_id"] == "it_password_reset"


def test_get_has_no_side_effect_called_twice(authed_client, db_session, test_account, monkeypatch, client):
    monkeypatch.setattr(settings, "enable_phishing_simulation", True)
    _verify_domain(db_session, test_account.account.id, "corp.example.com")
    created = authed_client.post(
        "/api/sim/campaigns",
        json={
            "name": "Rec test",
            "template_id": "it_password_reset",
            "recipients": [{"email": "alice@corp.example.com"}],
        },
    ).json()
    sent = authed_client.post(
        f"/api/sim/campaigns/{created['id']}/send", json={"authorization_accepted": True}
    ).json()
    token = sent["recipients"][0]["dry_run_tracking_url"].rsplit("/track/", 1)[1]
    client.get(f"/api/sim/track/{token}")

    first = authed_client.get("/api/human-risk/recommendations").json()
    second = authed_client.get("/api/human-risk/recommendations").json()
    assert first == second


def test_empty_when_nothing_has_failed(authed_client):
    response = authed_client.get("/api/human-risk/recommendations")
    assert response.json() == {"items": [], "total": 0}
