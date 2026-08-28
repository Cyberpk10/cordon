from __future__ import annotations

from datetime import datetime, timezone

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


def test_creating_a_campaign_with_recipient_on_unverified_domain_is_rejected(authed_client):
    response = authed_client.post(
        "/api/sim/campaigns",
        json={
            "name": "Q1 awareness test",
            "template_id": "it_password_reset",
            "recipients": [{"email": "alice@unverified.example"}],
        },
    )

    assert response.status_code == 400
    assert "unverified.example" in response.json()["detail"]


def test_creating_a_campaign_with_verified_recipient_succeeds(authed_client, db_session, test_account):
    _verify_domain(db_session, test_account.account.id, "corp.example.com")

    response = authed_client.post(
        "/api/sim/campaigns",
        json={
            "name": "Q1 awareness test",
            "template_id": "it_password_reset",
            "recipients": [{"email": "Alice@Corp.Example.com"}],
        },
    )

    assert response.status_code == 201
    body = response.json()
    assert body["status"] == "draft"
    assert len(body["recipients"]) == 1
    assert body["recipients"][0]["email"] == "alice@corp.example.com"
    assert body["recipients"][0]["status"] == "pending"


def test_campaign_rejects_a_mix_of_verified_and_unverified_domains(authed_client, db_session, test_account):
    _verify_domain(db_session, test_account.account.id, "corp.example.com")

    response = authed_client.post(
        "/api/sim/campaigns",
        json={
            "name": "Mixed",
            "template_id": "it_password_reset",
            "recipients": [
                {"email": "alice@corp.example.com"},
                {"email": "bob@other.example"},
            ],
        },
    )

    assert response.status_code == 400
    assert "other.example" in response.json()["detail"]
    assert "corp.example.com" not in response.json()["detail"]


def test_unknown_template_id_rejected(authed_client, db_session, test_account):
    _verify_domain(db_session, test_account.account.id, "corp.example.com")

    response = authed_client.post(
        "/api/sim/campaigns",
        json={
            "name": "Bad template",
            "template_id": "does_not_exist",
            "recipients": [{"email": "alice@corp.example.com"}],
        },
    )

    assert response.status_code == 400


def test_empty_recipient_list_rejected(authed_client):
    response = authed_client.post(
        "/api/sim/campaigns",
        json={"name": "Empty", "template_id": "it_password_reset", "recipients": []},
    )
    assert response.status_code == 422


def test_non_admin_cannot_create_campaign(analyst_authed_client):
    response = analyst_authed_client.post(
        "/api/sim/campaigns",
        json={
            "name": "Nope",
            "template_id": "it_password_reset",
            "recipients": [{"email": "alice@corp.example.com"}],
        },
    )
    assert response.status_code == 403


def test_get_campaign_cross_tenant_isolation(authed_client, other_account_authed_client, db_session, test_account):
    _verify_domain(db_session, test_account.account.id, "corp.example.com")
    created = authed_client.post(
        "/api/sim/campaigns",
        json={
            "name": "Mine",
            "template_id": "it_password_reset",
            "recipients": [{"email": "alice@corp.example.com"}],
        },
    ).json()

    response = other_account_authed_client.get(f"/api/sim/campaigns/{created['id']}")
    assert response.status_code == 404
