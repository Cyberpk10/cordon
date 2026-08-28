"""M9 Stage 2 — a phishing-simulation campaign must show up as evidence for the human-risk
controls (NIST PR.AT-01, ISO A.6.3, SOC2 CC1.4/CC2.2) even with zero analyzed Case rows,
without affecting any unrelated control.
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


def _send_campaign_with_a_click(authed_client, client) -> None:
    created = authed_client.post(
        "/api/sim/campaigns",
        json={
            "name": "Audit evidence test",
            "template_id": "it_password_reset",
            "recipients": [{"email": "alice@corp.example.com"}],
        },
    ).json()
    sent = authed_client.post(
        f"/api/sim/campaigns/{created['id']}/send", json={"authorization_accepted": True}
    ).json()
    token = sent["recipients"][0]["dry_run_tracking_url"].rsplit("/track/", 1)[1]
    client.get(f"/api/sim/track/{token}")


def test_nist_pr_at_01_operating_from_simulation_evidence_alone(
    authed_client, db_session, test_account, monkeypatch, client
):
    monkeypatch.setattr(settings, "enable_phishing_simulation", True)
    _verify_domain(db_session, test_account.account.id, "corp.example.com")
    _send_campaign_with_a_click(authed_client, client)

    body = authed_client.get("/api/audit/evidence", params={"framework": "nist"}).json()
    by_id = {c["control_id"]: c for c in body["controls"]}

    assert by_id["PR.AT-01"]["operating"] is True
    assert by_id["PR.AT-01"]["human_risk_evidence"]["campaigns_run"] == 1
    assert by_id["PR.AT-01"]["human_risk_evidence"]["distinct_employees_tested"] == 1
    assert by_id["PR.AT-01"]["human_risk_evidence"]["distinct_employees_trained"] == 1

    # An unrelated control (no case evidence, not in the human-risk mapping) stays untouched.
    unrelated = next(c for c in body["controls"] if c["control_id"] not in {"PR.AT-01"})
    assert unrelated["human_risk_evidence"] is None


def test_iso_a_6_3_operating_from_simulation_evidence_alone(
    authed_client, db_session, test_account, monkeypatch, client
):
    monkeypatch.setattr(settings, "enable_phishing_simulation", True)
    _verify_domain(db_session, test_account.account.id, "corp.example.com")
    _send_campaign_with_a_click(authed_client, client)

    body = authed_client.get("/api/audit/evidence", params={"framework": "iso"}).json()
    by_id = {c["control_id"]: c for c in body["controls"]}
    assert by_id["A.6.3"]["operating"] is True
    assert by_id["A.6.3"]["human_risk_evidence"]["campaigns_run"] == 1


def test_soc2_cc1_4_and_cc2_2_operating_from_simulation_evidence_alone(
    authed_client, db_session, test_account, monkeypatch, client
):
    monkeypatch.setattr(settings, "enable_phishing_simulation", True)
    _verify_domain(db_session, test_account.account.id, "corp.example.com")
    _send_campaign_with_a_click(authed_client, client)

    body = authed_client.get("/api/audit/evidence", params={"framework": "soc2"}).json()
    by_id = {c["control_id"]: c for c in body["controls"]}
    assert by_id["CC1.4"]["operating"] is True
    assert by_id["CC2.2"]["operating"] is True


def test_no_simulation_campaigns_gives_a_zeroed_human_risk_evidence_object(authed_client):
    """Mirrors evidence_for_framework's own convention (app/audit/aggregation.py): every
    control relevant to a given evidence source always gets an evidence entry, even with
    zero supporting activity — "checked, found nothing" (a zeroed object), not "not
    applicable" (null). Null is reserved for controls outside HUMAN_RISK_CONTROL_IDS
    entirely (see test_nist_pr_at_01_operating_from_simulation_evidence_alone's unrelated-
    control assertion)."""
    body = authed_client.get("/api/audit/evidence", params={"framework": "nist"}).json()
    by_id = {c["control_id"]: c for c in body["controls"]}
    assert by_id["PR.AT-01"]["operating"] is False
    assert by_id["PR.AT-01"]["human_risk_evidence"] == {
        "campaigns_run": 0,
        "distinct_employees_tested": 0,
        "distinct_employees_trained": 0,
        "sample_campaign_ids": [],
    }


def test_campaign_outside_the_period_does_not_count(authed_client, db_session, test_account, monkeypatch, client):
    monkeypatch.setattr(settings, "enable_phishing_simulation", True)
    _verify_domain(db_session, test_account.account.id, "corp.example.com")
    _send_campaign_with_a_click(authed_client, client)

    far_future = (datetime.now(timezone.utc).replace(year=2030)).isoformat()
    body = authed_client.get(
        "/api/audit/evidence",
        params={"framework": "nist", "date_from": far_future},
    ).json()
    by_id = {c["control_id"]: c for c in body["controls"]}
    assert by_id["PR.AT-01"]["operating"] is False
