"""D5 retired M6's automatic execution from the playbook fetch. Fetching a playbook is now
read-only: it never evaluates autonomy, never calls a connector (mock or the real Microsoft
Graph one), and writes no AutonomyAction rows, at any policy level, connected or not."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta

import pytest

from app.autonomy.executor import MockConnector
from app.autonomy.graph_connector import GraphConnector
from app.db.models import AutonomyAction, Case, GraphIntegration, Incident

CREDENTIAL_REQUEST = {
    "id": "CREDENTIAL_REQUEST", "category": "content", "title": "Credential request",
    "description": "d", "evidence": [], "severity": "high", "score": 90.0,
}
BRUTE_FORCE = {
    "id": "BRUTE_FORCE_PASSWORD_SPRAY", "category": "access", "title": "Brute force",
    "description": "d", "severity": "high", "points": 90.0, "evidence_event_ids": [],
}


@pytest.fixture(autouse=True)
def _connectors_must_not_run(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("a connector was called from an automatic path")

    for cls in (MockConnector, GraphConnector):
        monkeypatch.setattr(cls, "execute", boom)


def test_case_playbook_fetch_never_executes_at_any_level(authed_client, db_session, test_account):
    db_session.add(GraphIntegration(account_id=test_account.account.id, tenant_id="t-1", is_enabled=True))
    case = Case(id=uuid.uuid4(), account_id=test_account.account.id, filename="t.eml", verdict="malicious",
                score=90, from_addr="p@evil.com", subject="x", indicators=[CREDENTIAL_REQUEST],
                framework_mappings={})
    db_session.add(case)
    db_session.commit()
    authed_client.put("/api/autonomy/policy", json={
        "level": "L3", "rules": [{"action_type": "QUARANTINE_EMAIL", "min_confidence": 0.1, "full_auto": True}],
    })
    for _ in range(2):
        assert authed_client.post(f"/api/cases/{case.id}/remediate").status_code == 200
    assert db_session.query(AutonomyAction).filter(AutonomyAction.case_id == case.id).count() == 0


def test_incident_playbook_fetch_never_executes(authed_client, db_session, test_account):
    end = datetime(2026, 1, 6, 10, 6)
    incident = Incident(id=uuid.uuid4(), account_id=test_account.account.id, title="BF", actor="bob@corp.com",
                        verdict="suspicious", score=45, detection_types=["BRUTE_FORCE_PASSWORD_SPRAY"],
                        findings=[BRUTE_FORCE], framework_mappings={}, window_start=end - timedelta(hours=24),
                        window_end=end)
    db_session.add(incident)
    db_session.commit()
    authed_client.put("/api/autonomy/policy", json={
        "level": "L3", "rules": [{"action_type": "DISABLE_SESSION", "min_confidence": 0.1, "full_auto": True}],
    })
    assert authed_client.post(f"/api/incidents/{incident.id}/remediate").status_code == 200
    assert db_session.query(AutonomyAction).filter(AutonomyAction.incident_id == incident.id).count() == 0
