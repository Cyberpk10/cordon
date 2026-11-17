"""Account-takeover detection end to end: baselines built from real analyses (including clean
mail the add-on doesn't save), then the finding on /v1/analyze/email, the web analyze path,
and the Case."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app.db.models import Case, SenderObservation
from app.main import app

US, NG = "8.8.8.8", "105.112.0.1"


@pytest.fixture()
def api_key(authed_client) -> str:
    resp = authed_client.post("/v1/keys", json={"name": "Gmail add-on"})
    assert resp.status_code == 201, resp.text
    return resp.json()["key"]


def _eml(sender: str, body: str, *, origin_ip: str = US, msg_id: str = "1") -> str:
    domain = sender.rsplit("@", 1)[1]
    return "\r\n".join([
        f"Return-Path: <bounce@{domain}>",
        f"Received: from mail.{domain} (mail.{domain} [{US}]) by mx.example.com; Tue, 10 Nov 2026 15:00:00 +0000",
        f"Authentication-Results: mx.example.com; spf=pass smtp.mailfrom={domain}; dkim=pass "
        f"header.d={domain}; dmarc=pass header.from={domain}",
        f"From: Pat <{sender}>",
        "To: admin@example.com",
        "Subject: Monthly update",
        "Date: Tue, 10 Nov 2026 15:00:00 +0000",
        f"Message-ID: <{msg_id}@{domain}>",
        f"X-Originating-IP: [{origin_ip}]",
        'Content-Type: text/plain; charset="utf-8"',
        "",
        body,
    ])


PAYMENT_CHANGE = (
    "Hi, we have moved banks. Please update your records with our new bank account details "
    "before you pay this month's invoice. Thanks"
)


def _analyze(key: str, raw: str, persist: str = "if_not_clean"):
    c = TestClient(app)
    c.headers.update({"Authorization": f"Bearer {key}"})
    resp = c.post("/v1/analyze/email", json={"raw_email": raw, "persist": persist})
    assert resp.status_code == 200, resp.text
    return resp.json()


def _build_baseline(key: str, db_session, sender: str) -> None:
    """Three clean, authenticated emails from `sender`, spread over three weeks."""
    for i in range(3):
        body = _analyze(key, _eml(sender, f"Hi, here are the notes from meeting {i}. Thanks", msg_id=f"c{i}"))
        assert body["verdict"] == "clean" and body["account_takeover"] is None
    rows = db_session.query(SenderObservation).filter_by(from_addr=sender).all()
    for days, row in zip((21, 14, 7), rows):
        row.observed_at = datetime.now(timezone.utc) - timedelta(days=days)
    db_session.commit()


def test_takeover_fires_via_v1_after_a_baseline_built_from_unsaved_clean_mail(api_key, db_session):
    sender = "pat@acme-supplies.com"
    first = _analyze(api_key, _eml(sender, "Hi, first note. Thanks", msg_id="first"))
    assert first["sender_baseline"] == {
        "status": "first_contact", "summary": "First contact: no baseline for this sender yet.",
    }
    _build_baseline(api_key, db_session, sender)
    # Clean mail under if_not_clean: observations recorded, no Cases.
    assert db_session.query(Case).count() == 0
    assert db_session.query(SenderObservation).count() == 4

    body = _analyze(api_key, _eml(sender, PAYMENT_CHANGE, origin_ip=NG, msg_id="ato"))
    ato = body["account_takeover"]
    assert ato is not None and ato["kind"] == "external"
    assert "Nigeria" in ato["explanation"] and "United States" in ato["explanation"]
    assert "payment_change" in ato["intents"]
    assert body["sender_baseline"]["status"] == "established"
    assert body["verdict"] in {"suspicious", "malicious"}
    assert "MITRE T1078" in body["frameworks"]

    case = db_session.query(Case).one()  # not clean, so saved
    assert case.account_takeover["kind"] == "external"
    assert case.sender_baseline["status"] == "established"
    assert any(i["id"] == "ACCOUNT_TAKEOVER" for i in case.indicators)

    # Re-analysis of the same email: the saved Case is reused, the finding is still there,
    # and no observation is added.
    count = db_session.query(SenderObservation).count()
    again = _analyze(api_key, _eml(sender, PAYMENT_CHANGE, origin_ip=NG, msg_id="ato"))
    assert again["account_takeover"]["kind"] == "external"
    assert db_session.query(SenderObservation).count() == count


def test_traveller_stays_clean_end_to_end(api_key, db_session):
    sender = "pat@acme-supplies.com"
    _build_baseline(api_key, db_session, sender)
    body = _analyze(api_key, _eml(sender, "Greetings from the Lagos trade show! Notes to follow.", origin_ip=NG, msg_id="t"))
    assert body["verdict"] == "clean" and body["account_takeover"] is None
    assert body["sender_baseline"]["status"] == "established"


def test_a_harmless_email_first_does_not_hide_the_takeover_that_follows(api_key, db_session):
    sender = "pat@acme-supplies.com"
    _build_baseline(api_key, db_session, sender)
    harmless = _analyze(api_key, _eml(sender, "Greetings from Lagos! Notes to follow.", origin_ip=NG, msg_id="h"))
    assert harmless["verdict"] == "clean" and harmless["account_takeover"] is None
    body = _analyze(api_key, _eml(sender, PAYMENT_CHANGE, origin_ip=NG, msg_id="then-ato"))
    assert body["account_takeover"]["kind"] == "external"


def test_compromised_colleague_is_lateral(api_key, db_session):
    sender = "pat@example.com"  # the test account's own domain (its admin is admin@example.com)
    _build_baseline(api_key, db_session, sender)
    body = _analyze(api_key, _eml(sender, PAYMENT_CHANGE, origin_ip=NG, msg_id="lat"))
    assert body["account_takeover"]["kind"] == "lateral"
    assert "MITRE T1534" in body["frameworks"]


def test_assistant_never_records_an_observation(api_key, db_session):
    c = TestClient(app)
    c.headers.update({"Authorization": f"Bearer {api_key}"})
    resp = c.post("/v1/assistant", json={
        "raw_email": _eml("pat@acme-supplies.com", "Hello there", msg_id="a"), "question": "Is this phishing?",
    })
    assert resp.status_code == 200
    assert db_session.query(SenderObservation).count() == 0


def test_web_analyze_case_exposes_the_finding_and_baseline(authed_client, api_key, db_session):
    sender = "pat@acme-supplies.com"
    _build_baseline(api_key, db_session, sender)
    resp = authed_client.post(
        "/api/analyze/text", json={"raw_text": _eml(sender, PAYMENT_CHANGE, origin_ip=NG, msg_id="web")}
    )
    assert resp.status_code == 200, resp.text
    analyzed = resp.json()
    assert analyzed["account_takeover"]["kind"] == "external"
    detail = authed_client.get(f"/api/cases/{analyzed['id']}").json()
    assert detail["account_takeover"]["explanation"] == analyzed["account_takeover"]["explanation"]
    assert detail["sender_baseline"]["status"] == "established"
    assert detail["sender_baseline"]["message_count"] == 3


def test_observations_are_account_isolated(api_key, db_session, other_account_authed_client):
    sender = "pat@acme-supplies.com"
    _build_baseline(api_key, db_session, sender)
    other_key = other_account_authed_client.post("/v1/keys", json={"name": "x"}).json()["key"]
    body = _analyze(other_key, _eml(sender, PAYMENT_CHANGE, origin_ip=NG, msg_id="iso"))
    assert body["account_takeover"] is None
    assert body["sender_baseline"]["status"] == "first_contact"
