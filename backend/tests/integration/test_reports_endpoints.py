from __future__ import annotations

import json
import uuid
from datetime import datetime
from pathlib import Path

from app.db.models import (
    AutonomyAction,
    Case,
    EarlyWarningAlert,
    Incident,
    SecurityComplianceReport,
    SimulationCampaign,
    SimulationRecipient,
    SimulationTrainingRecommendation,
)

MITRE_T1598 = {"mitre_attack": [{"indicator_id": "URGENCY_LANGUAGE", "control_id": "T1598"}]}

_PERIOD = {"date_from": "2026-01-01T00:00:00", "date_to": "2026-01-31T23:59:59"}


def _make_case(db_session, account_id, *, verdict, created_at, framework_mappings=None):
    case = Case(
        id=uuid.uuid4(),
        account_id=account_id,
        created_at=created_at,
        filename="t.eml",
        verdict=verdict,
        score=70,
        from_addr="attacker@evil.example",
        subject="s",
        indicators=[],
        framework_mappings=framework_mappings or {},
    )
    db_session.add(case)
    db_session.commit()
    db_session.refresh(case)
    return case


def _make_incident(db_session, account_id, *, created_at):
    incident = Incident(
        id=uuid.uuid4(),
        account_id=account_id,
        created_at=created_at,
        title="t",
        actor="alice@corp.example",
        verdict="malicious",
        score=90,
        detection_types=["BRUTE_FORCE_PASSWORD_SPRAY"],
        findings=[],
        framework_mappings={},
        window_start=created_at,
        window_end=created_at,
    )
    db_session.add(incident)
    db_session.commit()
    return incident


def _make_executed_autonomy_action(db_session, account_id, case_id, *, created_at):
    action = AutonomyAction(
        id=uuid.uuid4(),
        account_id=account_id,
        created_at=created_at,
        case_id=case_id,
        trigger_finding_id="CREDENTIAL_REQUEST",
        action_type="QUARANTINE_EMAIL",
        target="victim@corp.example",
        confidence=0.9,
        decision="auto_execute",
        status="executed",
        reversible=True,
        mapped_controls={},
    )
    db_session.add(action)
    db_session.commit()
    return action


def _make_early_warning_alert(db_session, account_id, *, created_at):
    alert = EarlyWarningAlert(
        id=uuid.uuid4(),
        account_id=account_id,
        actor="bob@corp.example",
        status="active",
        score=70.0,
        signal_timeline=[],
        recommended_actions=[],
        created_at=created_at,
    )
    db_session.add(alert)
    db_session.commit()
    return alert


def _make_simulation_data(db_session, account_id, *, sent_at):
    campaign = SimulationCampaign(
        id=uuid.uuid4(),
        account_id=account_id,
        name="Q1 Campaign",
        template_id="paypal-verify",
        status="sent",
        sent_at=sent_at,
    )
    db_session.add(campaign)
    db_session.flush()

    clicked = SimulationRecipient(
        id=uuid.uuid4(),
        account_id=account_id,
        campaign_id=campaign.id,
        email="clicked@corp.example",
        status="clicked",
        clicked_at=sent_at,
    )
    reported = SimulationRecipient(
        id=uuid.uuid4(),
        account_id=account_id,
        campaign_id=campaign.id,
        email="reported@corp.example",
        status="sent",
        reported_at=sent_at,
    )
    db_session.add_all([clicked, reported])

    training = SimulationTrainingRecommendation(
        id=uuid.uuid4(),
        account_id=account_id,
        recipient="clicked@corp.example",
        template_id="paypal-verify",
        template_name="PayPal Verify",
        risk_score=80,
        recommendation="Retake phishing awareness training.",
        first_flagged_at=sent_at,
        updated_at=sent_at,
    )
    db_session.add(training)
    db_session.commit()
    return campaign


def _seed_full_period(db_session, account_id):
    _make_case(db_session, account_id, verdict="malicious", created_at=datetime(2026, 1, 5), framework_mappings=MITRE_T1598)
    case_b = _make_case(db_session, account_id, verdict="suspicious", created_at=datetime(2026, 1, 10))
    _make_case(db_session, account_id, verdict="safe", created_at=datetime(2026, 1, 11))
    # Outside the period — must not be counted.
    _make_case(db_session, account_id, verdict="malicious", created_at=datetime(2025, 6, 1))

    _make_incident(db_session, account_id, created_at=datetime(2026, 1, 6))
    _make_executed_autonomy_action(db_session, account_id, case_b.id, created_at=datetime(2026, 1, 10))
    _make_early_warning_alert(db_session, account_id, created_at=datetime(2026, 1, 7))
    _make_simulation_data(db_session, account_id, sent_at=datetime(2026, 1, 8))


def test_generate_report_reflects_seeded_data_exactly(authed_client, db_session, test_account):
    _seed_full_period(db_session, test_account.account.id)

    response = authed_client.post("/api/reports/security-compliance", json=_PERIOD)

    assert response.status_code == 200
    body = response.json()
    assert body["emails_analyzed"] == 3
    assert body["verdict_breakdown"] == {"malicious": 1, "suspicious": 1, "safe": 1}
    assert body["threats_detected"] == 2
    assert body["threats_contained"] == 1
    assert body["exposure_avoided_usd"] > 0
    assert body["incidents_detected"] == 1
    assert body["early_warning_alerts_raised"] == 1
    assert body["human_risk"]["campaigns_run"] == 1
    assert body["human_risk"]["employees_tested"] == 2
    assert body["human_risk"]["employees_clicked"] == 1
    assert body["human_risk"]["employees_reported"] == 1
    assert body["human_risk"]["employees_flagged_for_training"] == 1
    assert body["has_any_activity"] is True
    assert body["account_name"] == test_account.account.name
    assert body["executive_summary"]["source"] == "deterministic"
    assert str(body["threats_detected"]) in body["executive_summary"]["text"] or "2" in body["executive_summary"]["text"]

    fw_by_key = {f["framework_key"]: f for f in body["framework_coverage"]}
    assert fw_by_key["mitre_attack"]["covered_controls"] >= 1


def test_generate_report_for_an_empty_account_is_honest_not_padded(authed_client):
    response = authed_client.post("/api/reports/security-compliance", json=_PERIOD)

    assert response.status_code == 200
    body = response.json()
    assert body["emails_analyzed"] == 0
    assert body["threats_detected"] == 0
    assert body["threats_contained"] == 0
    assert body["exposure_avoided_usd"] == 0.0
    assert body["incidents_detected"] == 0
    assert body["early_warning_alerts_raised"] == 0
    assert body["has_any_activity"] is False
    assert "no" in body["executive_summary"]["text"].lower()


def test_generate_report_persists_row_and_downloadable_files(authed_client, db_session, test_account):
    _seed_full_period(db_session, test_account.account.id)

    response = authed_client.post("/api/reports/security-compliance", json=_PERIOD)
    report_id = response.json()["id"]

    row = db_session.get(SecurityComplianceReport, uuid.UUID(report_id))
    assert row is not None
    assert row.emails_analyzed == 3
    assert row.threats_detected == 2

    pdf_path = Path(row.pdf_path)
    json_path = Path(row.json_path)
    assert pdf_path.exists()
    assert json_path.exists()
    assert pdf_path.read_bytes()[:4] == b"%PDF"

    payload = json.loads(json_path.read_text())["cordon_security_compliance_report"]
    assert payload["emails_analyzed"] == 3
    assert payload["threats_detected"] == 2


def test_list_reports_includes_generated_report(authed_client, db_session, test_account):
    _seed_full_period(db_session, test_account.account.id)
    create_response = authed_client.post("/api/reports/security-compliance", json=_PERIOD)
    report_id = create_response.json()["id"]

    list_response = authed_client.get("/api/reports/security-compliance")

    assert list_response.status_code == 200
    body = list_response.json()
    assert body["total"] == 1
    assert body["items"][0]["id"] == report_id
    assert body["items"][0]["emails_analyzed"] == 3


def test_get_report_by_id_returns_full_detail(authed_client, db_session, test_account):
    _seed_full_period(db_session, test_account.account.id)
    create_response = authed_client.post("/api/reports/security-compliance", json=_PERIOD)
    report_id = create_response.json()["id"]

    response = authed_client.get(f"/api/reports/security-compliance/{report_id}")

    assert response.status_code == 200
    body = response.json()
    assert body["id"] == report_id
    assert body["emails_analyzed"] == 3
    assert body["framework_coverage"]


def test_get_nonexistent_report_returns_404(authed_client):
    response = authed_client.get(f"/api/reports/security-compliance/{uuid.uuid4()}")
    assert response.status_code == 404


def test_download_report_returns_stored_bytes_for_both_formats(authed_client, db_session, test_account):
    _seed_full_period(db_session, test_account.account.id)
    create_response = authed_client.post("/api/reports/security-compliance", json=_PERIOD)
    report_id = create_response.json()["id"]
    row = db_session.get(SecurityComplianceReport, uuid.UUID(report_id))

    pdf_response = authed_client.get(
        f"/api/reports/security-compliance/{report_id}/download", params={"format": "pdf"}
    )
    assert pdf_response.status_code == 200
    assert pdf_response.headers["content-type"] == "application/pdf"
    assert pdf_response.content == Path(row.pdf_path).read_bytes()

    json_response = authed_client.get(
        f"/api/reports/security-compliance/{report_id}/download", params={"format": "json"}
    )
    assert json_response.status_code == 200
    assert json_response.headers["content-type"] == "application/json"
    assert json_response.content == Path(row.json_path).read_bytes()


def test_download_nonexistent_report_returns_404(authed_client):
    response = authed_client.get(
        f"/api/reports/security-compliance/{uuid.uuid4()}/download", params={"format": "pdf"}
    )
    assert response.status_code == 404


def test_unauthenticated_request_is_rejected(client):
    response = client.post("/api/reports/security-compliance", json=_PERIOD)
    assert response.status_code == 401
