"""Required test: the stored training recommendation must match the exact lure/template
type the employee actually fell for, and must update to the most recent one across
campaigns.
"""

from __future__ import annotations

from datetime import datetime, timezone

from app.core.config import settings
from app.db.models import SimulationDomain, SimulationTrainingRecommendation


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


def _send_campaign(authed_client, template_id: str, email: str) -> dict:
    created = authed_client.post(
        "/api/sim/campaigns",
        json={
            "name": f"Campaign for {template_id}",
            "template_id": template_id,
            "recipients": [{"email": email, "department": "Sales"}],
        },
    ).json()
    return authed_client.post(
        f"/api/sim/campaigns/{created['id']}/send", json={"authorization_accepted": True}
    ).json()


def _token_from_send_response(sent: dict) -> str:
    return sent["recipients"][0]["dry_run_tracking_url"].rsplit("/track/", 1)[1]


def test_clicking_creates_a_recommendation_referencing_that_template(
    authed_client, db_session, test_account, monkeypatch, client
):
    monkeypatch.setattr(settings, "enable_phishing_simulation", True)
    _verify_domain(db_session, test_account.account.id, "corp.example.com")

    sent = _send_campaign(authed_client, "it_password_reset", "alice@corp.example.com")
    token = _token_from_send_response(sent)
    client.get(f"/api/sim/track/{token}")

    row = db_session.query(SimulationTrainingRecommendation).one()
    assert row.recipient == "alice@corp.example.com"
    assert row.template_id == "it_password_reset"
    assert row.risk_score == 20
    assert "it_password_reset" in row.recommendation or "IT" in row.recommendation


def test_failing_a_second_different_template_updates_the_recommendation_to_reference_it(
    authed_client, db_session, test_account, monkeypatch, client
):
    monkeypatch.setattr(settings, "enable_phishing_simulation", True)
    _verify_domain(db_session, test_account.account.id, "corp.example.com")

    first_sent = _send_campaign(authed_client, "it_password_reset", "alice@corp.example.com")
    client.get(f"/api/sim/track/{_token_from_send_response(first_sent)}")

    second_sent = _send_campaign(authed_client, "hr_benefits_deadline", "alice@corp.example.com")
    client.get(
        f"/api/sim/track/{_token_from_send_response(second_sent)}", params={"event": "submit"}
    )

    # Still exactly one row (upsert by unique (account_id, recipient), not a new row).
    row = db_session.query(SimulationTrainingRecommendation).one()
    assert row.template_id == "hr_benefits_deadline"
    assert row.risk_score == 20 + 40  # both failures accumulate in the risk score


def test_a_click_that_is_immediately_reported_still_creates_a_recommendation(
    authed_client, db_session, test_account, monkeypatch, client
):
    """Clicking is already a failure — reporting afterward doesn't erase that it happened,
    it only lowers the running score (covered in the scoring unit tests)."""
    monkeypatch.setattr(settings, "enable_phishing_simulation", True)
    _verify_domain(db_session, test_account.account.id, "corp.example.com")

    sent = _send_campaign(authed_client, "it_password_reset", "alice@corp.example.com")
    token = _token_from_send_response(sent)
    client.get(f"/api/sim/track/{token}")
    client.get(f"/api/sim/track/{token}", params={"event": "report"})

    row = db_session.query(SimulationTrainingRecommendation).one()
    assert row.template_id == "it_password_reset"
    # The fast report lowers the stored snapshot below the raw click penalty.
    assert row.risk_score < 20


def test_cross_tenant_isolation_of_recommendations(
    authed_client, other_account_authed_client, db_session, test_account, monkeypatch, client
):
    monkeypatch.setattr(settings, "enable_phishing_simulation", True)
    _verify_domain(db_session, test_account.account.id, "corp.example.com")

    sent = _send_campaign(authed_client, "it_password_reset", "alice@corp.example.com")
    client.get(f"/api/sim/track/{_token_from_send_response(sent)}")

    other_response = other_account_authed_client.get("/api/human-risk/recommendations")
    assert other_response.json()["items"] == []
