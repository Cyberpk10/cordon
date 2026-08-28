"""Smoke test: generating a full Audit Mode report (JSON + PDF) succeeds and the JSON
includes the human_risk section for the relevant controls, when phishing-simulation
evidence exists.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from app.core.config import settings
from app.db.models import AuditReport, SimulationDomain


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


def test_generated_report_json_includes_human_risk_section(
    authed_client, db_session, test_account, monkeypatch, client
):
    monkeypatch.setattr(settings, "enable_phishing_simulation", True)
    _verify_domain(db_session, test_account.account.id, "corp.example.com")
    created = authed_client.post(
        "/api/sim/campaigns",
        json={
            "name": "Report smoke test",
            "template_id": "it_password_reset",
            "recipients": [{"email": "alice@corp.example.com"}],
        },
    ).json()
    sent = authed_client.post(
        f"/api/sim/campaigns/{created['id']}/send", json={"authorization_accepted": True}
    ).json()
    token = sent["recipients"][0]["dry_run_tracking_url"].rsplit("/track/", 1)[1]
    client.get(f"/api/sim/track/{token}")

    generate_response = authed_client.post("/api/audit/report", json={"framework": "nist"})
    assert generate_response.status_code == 200
    report_id = generate_response.json()["id"]

    report = db_session.get(AuditReport, uuid.UUID(report_id))
    json_bytes = open(report.json_path, "rb").read()
    payload = json.loads(json_bytes)["aegis_audit_evidence_pack"]
    by_id = {c["control_id"]: c for c in payload["controls"]}
    assert by_id["PR.AT-01"]["human_risk"]["campaigns_run"] == 1

    pdf_response = authed_client.get(f"/api/audit/reports/{report_id}/download", params={"format": "pdf"})
    assert pdf_response.status_code == 200
    assert pdf_response.headers["content-type"] == "application/pdf"
