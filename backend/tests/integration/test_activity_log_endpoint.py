from __future__ import annotations

MALICIOUS_FIXTURE = """timestamp,account,source_ip,geo,result
2026-10-15T02:08:41Z,j.carter@northstar-clinic.org,185.220.101.44,RU,FAIL
2026-10-15T02:08:43Z,m.flores@northstar-clinic.org,185.220.101.44,RU,FAIL
2026-10-15T02:08:45Z,a.singh@northstar-clinic.org,185.220.101.44,RU,FAIL
2026-10-15T02:08:47Z,d.reyes@northstar-clinic.org,185.220.101.44,RU,FAIL
2026-10-15T02:08:49Z,t.owens@northstar-clinic.org,185.220.101.44,RU,FAIL
2026-10-15T02:11:02Z,admin@northstar-clinic.org,185.220.101.44,RU,FAIL
2026-10-15T02:11:05Z,admin@northstar-clinic.org,185.220.101.44,RU,FAIL
2026-10-15T02:11:08Z,admin@northstar-clinic.org,185.220.101.44,RU,FAIL
2026-10-15T02:14:50Z,admin@northstar-clinic.org,185.220.101.44,RU,SUCCESS
2026-10-15T02:15:12Z,admin@northstar-clinic.org,185.220.101.44,RU,MFA_DISABLED
2026-10-15T02:16:40Z,admin@northstar-clinic.org,185.220.101.44,RU,MAIL_RULE_CREATED
2026-10-15T02:18:03Z,admin@northstar-clinic.org,185.220.101.44,RU,BULK_DOWNLOAD
"""

BENIGN_FIXTURE = """timestamp,account,source_ip,geo,result
2026-10-15T14:02:11Z,j.carter@northstar-clinic.org,203.0.113.10,US,SUCCESS
2026-10-15T14:31:45Z,j.carter@northstar-clinic.org,203.0.113.10,US,SUCCESS
2026-10-15T15:10:02Z,j.carter@northstar-clinic.org,203.0.113.10,US,SUCCESS
2026-10-15T16:05:19Z,j.carter@northstar-clinic.org,203.0.113.10,US,SUCCESS
2026-10-15T16:47:33Z,j.carter@northstar-clinic.org,203.0.113.10,US,SUCCESS
"""

_URL = "/api/activity-log/analyze"


def test_malicious_fixture_scores_malicious_and_high_risk(authed_client):
    response = authed_client.post(_URL, json={"raw_text": MALICIOUS_FIXTURE})
    assert response.status_code == 200
    body = response.json()
    assert body["verdict"] == "malicious"
    assert body["score"] > 54
    assert body["summary"]["event_count"] == 12
    assert body["summary"]["primary_actor"] == "admin@northstar-clinic.org"
    indicator_ids = {i["id"] for i in body["indicators"]}
    assert "PRIVILEGE_ESCALATION" in indicator_ids
    assert "DATA_EXFIL_LARGE_TRANSFER" in indicator_ids


def test_benign_fixture_scores_safe_and_low_risk(authed_client):
    response = authed_client.post(_URL, json={"raw_text": BENIGN_FIXTURE})
    assert response.status_code == 200
    body = response.json()
    assert body["verdict"] == "safe"
    assert body["score"] == 0
    assert body["indicators"] == []
    assert body["summary"]["event_count"] == 5


def test_malicious_fixture_framework_mappings_are_populated(authed_client):
    response = authed_client.post(_URL, json={"raw_text": MALICIOUS_FIXTURE})
    body = response.json()
    assert body["framework_mappings"]
    assert any(len(refs) > 0 for refs in body["framework_mappings"].values())


def test_empty_pasted_log_returns_400_not_500(authed_client):
    response = authed_client.post(_URL, json={"raw_text": "   "})
    assert response.status_code == 400


def test_bad_header_returns_400_not_500(authed_client):
    response = authed_client.post(_URL, json={"raw_text": "foo,bar,baz\n1,2,3\n"})
    assert response.status_code == 400
    assert "header" in response.json()["detail"].lower()


def test_garbage_input_returns_400_not_500(authed_client):
    response = authed_client.post(_URL, json={"raw_text": "this is not a csv at all, just prose."})
    assert response.status_code == 400


def test_unauthenticated_request_is_rejected(client):
    response = client.post(_URL, json={"raw_text": MALICIOUS_FIXTURE})
    assert response.status_code == 401


def test_persists_incident_scoped_to_the_authenticated_account(authed_client, db_session, test_account):
    from app.db.models import Incident

    before = db_session.query(Incident).filter(Incident.account_id == test_account.account.id).count()
    response = authed_client.post(_URL, json={"raw_text": MALICIOUS_FIXTURE})
    assert response.status_code == 200
    after = db_session.query(Incident).filter(Incident.account_id == test_account.account.id).count()
    assert after == before + 1


def test_result_is_not_visible_to_a_different_account(
    authed_client, other_account_authed_client, db_session, test_account
):
    from app.db.models import Incident

    authed_client.post(_URL, json={"raw_text": MALICIOUS_FIXTURE})
    victim_incident = (
        db_session.query(Incident).filter(Incident.account_id == test_account.account.id).first()
    )
    assert victim_incident is not None

    # The other account pasting its own (benign) log must never see the victim's incident.
    cross_response = other_account_authed_client.post(_URL, json={"raw_text": BENIGN_FIXTURE})
    assert cross_response.status_code == 200
    assert cross_response.json()["verdict"] == "safe"
