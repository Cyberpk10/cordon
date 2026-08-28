"""Required test: risk score must be demonstrably higher after a second failure than after
the first, and lower again after a report — verified end-to-end through the live
GET /api/human-risk/summary endpoint (whose score is always freshly computed, not read from
the stored snapshot).
"""

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


def _send_campaign(authed_client, template_id: str, email: str, department: str | None = None) -> dict:
    created = authed_client.post(
        "/api/sim/campaigns",
        json={
            "name": f"Campaign for {template_id}",
            "template_id": template_id,
            "recipients": [{"email": email, "department": department}],
        },
    ).json()
    return authed_client.post(
        f"/api/sim/campaigns/{created['id']}/send", json={"authorization_accepted": True}
    ).json()


def _token(sent: dict) -> str:
    return sent["recipients"][0]["dry_run_tracking_url"].rsplit("/track/", 1)[1]


def _riskiest_score(authed_client, email: str) -> int:
    body = authed_client.get("/api/human-risk/summary").json()
    row = next(r for r in body["riskiest_users"] if r["email"] == email)
    return row["risk_score"]


def test_risk_score_rises_after_a_second_failure(authed_client, db_session, test_account, monkeypatch, client):
    monkeypatch.setattr(settings, "enable_phishing_simulation", True)
    _verify_domain(db_session, test_account.account.id, "corp.example.com")

    first = _send_campaign(authed_client, "it_password_reset", "alice@corp.example.com")
    client.get(f"/api/sim/track/{_token(first)}")
    score_after_one = _riskiest_score(authed_client, "alice@corp.example.com")

    second = _send_campaign(authed_client, "hr_benefits_deadline", "alice@corp.example.com")
    client.get(f"/api/sim/track/{_token(second)}")
    score_after_two = _riskiest_score(authed_client, "alice@corp.example.com")

    assert score_after_two > score_after_one


def test_risk_score_falls_after_a_report(authed_client, db_session, test_account, monkeypatch, client):
    monkeypatch.setattr(settings, "enable_phishing_simulation", True)
    _verify_domain(db_session, test_account.account.id, "corp.example.com")

    sent = _send_campaign(authed_client, "it_password_reset", "alice@corp.example.com")
    token = _token(sent)
    client.get(f"/api/sim/track/{token}")
    score_after_click = _riskiest_score(authed_client, "alice@corp.example.com")

    client.get(f"/api/sim/track/{token}", params={"event": "report"})
    score_after_report = _riskiest_score(authed_client, "alice@corp.example.com")

    assert score_after_report < score_after_click


def test_department_breakdown_reflects_supplied_department(
    authed_client, db_session, test_account, monkeypatch, client
):
    monkeypatch.setattr(settings, "enable_phishing_simulation", True)
    _verify_domain(db_session, test_account.account.id, "corp.example.com")

    sent = _send_campaign(authed_client, "it_password_reset", "alice@corp.example.com", department="Sales")
    client.get(f"/api/sim/track/{_token(sent)}")

    body = authed_client.get("/api/human-risk/summary").json()
    departments = {row["department"] for row in body["department_breakdown"]}
    assert "Sales" in departments


def test_lure_effectiveness_ranks_higher_click_rate_first(
    authed_client, db_session, test_account, monkeypatch, client
):
    monkeypatch.setattr(settings, "enable_phishing_simulation", True)
    _verify_domain(db_session, test_account.account.id, "corp.example.com")

    clicked_sent = _send_campaign(authed_client, "it_password_reset", "alice@corp.example.com")
    client.get(f"/api/sim/track/{_token(clicked_sent)}")
    _send_campaign(authed_client, "hr_benefits_deadline", "bob@corp.example.com")  # never clicked

    body = authed_client.get("/api/human-risk/summary").json()
    lures = {row["template_id"]: row for row in body["lure_effectiveness"]}
    assert lures["it_password_reset"]["click_rate"] == 1.0
    assert lures["hr_benefits_deadline"]["click_rate"] == 0.0


def test_click_rate_over_time_has_at_least_one_bucket_after_a_send(
    authed_client, db_session, test_account, monkeypatch, client
):
    monkeypatch.setattr(settings, "enable_phishing_simulation", True)
    _verify_domain(db_session, test_account.account.id, "corp.example.com")
    _send_campaign(authed_client, "it_password_reset", "alice@corp.example.com")

    body = authed_client.get("/api/human-risk/summary").json()
    assert len(body["click_rate_over_time"]) >= 1


def test_non_admin_can_read_the_summary(analyst_authed_client):
    response = analyst_authed_client.get("/api/human-risk/summary")
    assert response.status_code == 200


def test_cross_tenant_isolation_of_summary(
    authed_client, other_account_authed_client, db_session, test_account, monkeypatch, client
):
    monkeypatch.setattr(settings, "enable_phishing_simulation", True)
    _verify_domain(db_session, test_account.account.id, "corp.example.com")
    sent = _send_campaign(authed_client, "it_password_reset", "alice@corp.example.com")
    client.get(f"/api/sim/track/{_token(sent)}")

    other_body = other_account_authed_client.get("/api/human-risk/summary").json()
    assert other_body["riskiest_users"] == []
