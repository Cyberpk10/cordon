from __future__ import annotations

from app.db.models import SimulationDomain


def test_first_verify_call_creates_pending_row_with_instructions(authed_client, db_session, test_account):
    response = authed_client.post("/api/sim/domains/verify", json={"domain": "Corp.Example.com"})

    assert response.status_code == 200
    body = response.json()
    assert body["domain"] == "corp.example.com"
    assert body["status"] == "pending"
    assert body["verification_record_name"] == "_cordon-verify.corp.example.com"
    assert body["verification_record_value"].startswith("cordon-domain-verification=")
    assert body["verified_at"] is None

    row = db_session.query(SimulationDomain).filter(SimulationDomain.account_id == test_account.account.id).one()
    assert row.domain == "corp.example.com"
    assert row.status == "pending"


def test_second_call_flips_to_verified_when_dns_matches(authed_client, monkeypatch, test_account):
    authed_client.post("/api/sim/domains/verify", json={"domain": "corp.example.com"})

    monkeypatch.setattr("app.api.routes.simulation.domain_is_verified_by", lambda token, domain: True)
    response = authed_client.post("/api/sim/domains/verify", json={"domain": "corp.example.com"})

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "verified"
    assert body["verified_at"] is not None


def test_second_call_stays_pending_when_dns_does_not_match(authed_client, monkeypatch):
    authed_client.post("/api/sim/domains/verify", json={"domain": "corp.example.com"})

    monkeypatch.setattr("app.api.routes.simulation.domain_is_verified_by", lambda token, domain: False)
    response = authed_client.post("/api/sim/domains/verify", json={"domain": "corp.example.com"})

    assert response.status_code == 200
    assert response.json()["status"] == "pending"


def test_already_verified_domain_is_idempotent(authed_client, monkeypatch):
    authed_client.post("/api/sim/domains/verify", json={"domain": "corp.example.com"})
    monkeypatch.setattr("app.api.routes.simulation.domain_is_verified_by", lambda token, domain: True)
    first = authed_client.post("/api/sim/domains/verify", json={"domain": "corp.example.com"})
    verified_at = first.json()["verified_at"]

    second = authed_client.post("/api/sim/domains/verify", json={"domain": "corp.example.com"})
    assert second.json()["status"] == "verified"
    assert second.json()["verified_at"] == verified_at


def test_malformed_domain_rejected(authed_client):
    response = authed_client.post("/api/sim/domains/verify", json={"domain": "not a domain"})
    assert response.status_code == 400


def test_non_admin_cannot_verify_domains(analyst_authed_client):
    response = analyst_authed_client.post("/api/sim/domains/verify", json={"domain": "corp.example.com"})
    assert response.status_code == 403


def test_domain_verification_is_isolated_per_account(authed_client, other_account_authed_client, db_session):
    authed_client.post("/api/sim/domains/verify", json={"domain": "shared.example.com"})
    other_account_authed_client.post("/api/sim/domains/verify", json={"domain": "shared.example.com"})

    rows = db_session.query(SimulationDomain).filter(SimulationDomain.domain == "shared.example.com").all()
    assert len(rows) == 2
    assert rows[0].account_id != rows[1].account_id
    assert rows[0].verification_token != rows[1].verification_token
