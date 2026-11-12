"""Public /v1 API: API-key lifecycle and POST /v1/analyze/email (the Gmail add-on's call)."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from app.db.models import ApiKey, AuditLogEntry, Case, User
from app.main import app

CONTRACT_KEYS = {"verdict", "score", "category", "summary", "top_indicators", "auth", "frameworks"}


@pytest.fixture()
def api_key(authed_client) -> str:
    resp = authed_client.post("/v1/keys", json={"name": "Gmail add-on"})
    assert resp.status_code == 201, resp.text
    return resp.json()["key"]


def _key_client(key: str | None) -> TestClient:
    c = TestClient(app)
    if key is not None:
        c.headers.update({"Authorization": f"Bearer {key}"})
    return c


def _analyze(key: str | None, raw: str):
    return _key_client(key).post("/v1/analyze/email", json={"raw_email": raw})


# ---- key lifecycle ---------------------------------------------------------------------------


def test_minted_key_is_shown_once_and_stored_hashed(authed_client, db_session):
    body = authed_client.post("/v1/keys", json={"name": "Gmail add-on"}).json()
    assert body["key"].startswith("cdn_") and len(body["key"]) > 40
    assert body["key"].startswith(body["prefix"]) and body["prefix"] != body["key"]

    row = db_session.query(ApiKey).one()
    assert row.key_hash != body["key"] and body["key"] not in row.key_hash
    listed = authed_client.get("/v1/keys").json()["keys"]
    assert [k["id"] for k in listed] == [body["id"]]
    assert "key" not in listed[0]
    assert db_session.query(AuditLogEntry).filter_by(event_type="api_key_created").count() == 1


def test_minting_requires_a_logged_in_user(client):
    assert client.post("/v1/keys", json={"name": "x"}).status_code == 401


def test_revoked_key_stops_working(authed_client, api_key, load_eml):
    key_id = authed_client.get("/v1/keys").json()["keys"][0]["id"]
    assert authed_client.delete(f"/v1/keys/{key_id}").status_code == 204
    assert _analyze(api_key, "Subject: hi\n\nhello").status_code == 401


def test_key_of_deactivated_user_stops_working(api_key, db_session, test_account):
    user = db_session.get(User, test_account.user.id)
    user.is_active = False
    db_session.commit()
    assert _analyze(api_key, "Subject: hi\n\nhello").status_code == 401


def test_cannot_revoke_another_accounts_key(api_key, other_account_authed_client, authed_client):
    key_id = authed_client.get("/v1/keys").json()["keys"][0]["id"]
    assert other_account_authed_client.delete(f"/v1/keys/{key_id}").status_code == 404
    assert other_account_authed_client.get("/v1/keys").json()["keys"] == []


# ---- analyze ---------------------------------------------------------------------------------


def test_malicious_sample_returns_malicious_with_indicators(api_key, load_eml, db_session, test_account):
    raw = load_eml("phishing_lookalike_paypal.eml").decode("utf-8")
    resp = _analyze(api_key, raw)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert set(body) == CONTRACT_KEYS
    assert body["verdict"] == "malicious"
    assert 0 <= body["score"] <= 100
    assert 1 <= len(body["top_indicators"]) <= 3 and all(body["top_indicators"])
    assert body["auth"] == {"spf": "fail", "dkim": "fail", "dmarc": "fail"}
    assert any(t.startswith("MITRE ") for t in body["frameworks"])
    assert body["summary"].startswith(f"Malicious ({body['score']}/100)")

    # Same pipeline and persistence as the web app: a normal Case in the key's account.
    case = db_session.query(Case).one()
    assert case.account_id == test_account.account.id
    assert case.score == body["score"] and case.verdict == "malicious"


def test_result_matches_the_web_apps_paste_analyze(api_key, load_eml, other_account_authed_client):
    """Same pipeline, not a fork: identical score/verdict/indicators to /api/analyze/text
    (run in a different account so sender history can't differ)."""
    raw = load_eml("phishing_bec_wire_transfer.eml").decode("utf-8")
    v1 = _analyze(api_key, raw).json()
    web = other_account_authed_client.post("/api/analyze/text", json={"raw_text": raw}).json()
    assert v1["score"] == web["score"]
    assert v1["verdict"] == web["verdict"]
    top = sorted(web["indicators"], key=lambda i: i["score"], reverse=True)[:3]
    assert v1["top_indicators"] == [i["title"] for i in top]


def test_benign_sample_is_clean(api_key, load_eml):
    body = _analyze(api_key, load_eml("benign_newsletter.eml").decode("utf-8")).json()
    assert body["verdict"] == "clean"
    assert body["auth"] == {"spf": "pass", "dkim": "pass", "dmarc": "pass"}


def test_reopening_the_same_email_returns_the_same_result_without_a_new_case(api_key, load_eml, db_session):
    raw = load_eml("phishing_shortener_credential_harvest.eml").decode("utf-8")
    first = _analyze(api_key, raw).json()
    second = _analyze(api_key, raw).json()
    assert first == second
    assert db_session.query(Case).count() == 1


def test_last_used_at_is_recorded(api_key, db_session):
    _analyze(api_key, "Subject: hi\n\nhello")
    db_session.expire_all()
    assert db_session.query(ApiKey).one().last_used_at is not None


@pytest.mark.parametrize("header", [None, "Bearer", "Bearer cdn_not-a-real-key", "Basic abc", "cdn_raw-without-bearer"])
def test_missing_or_invalid_key_is_401(header, db_session):
    c = TestClient(app)
    if header is not None:
        c.headers.update({"Authorization": header})
    resp = c.post("/v1/analyze/email", json={"raw_email": "Subject: hi\n\nhello"})
    assert resp.status_code == 401
    assert db_session.query(Case).count() == 0


def test_a_session_jwt_is_not_accepted_as_an_api_key(test_account):
    assert _analyze(test_account.token, "Subject: hi\n\nhello").status_code == 401


@pytest.mark.parametrize(
    "body",
    [{}, {"raw_email": 123}, {"raw_email": ""}, {"raw_email": "   \n "}, {"email": "Subject: x"}, [], "not json"],
)
def test_malformed_body_is_422(api_key, body):
    c = _key_client(api_key)
    if isinstance(body, str):
        resp = c.post("/v1/analyze/email", content=body, headers={"Content-Type": "application/json"})
    else:
        resp = c.post("/v1/analyze/email", json=body)
    assert resp.status_code == 422


def test_oversized_email_is_413(api_key, monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "max_upload_bytes", 100)
    assert _analyze(api_key, "Subject: hi\n\n" + "x" * 200).status_code == 413


def test_rate_limited_per_key(authed_client, monkeypatch):
    key_a = authed_client.post("/v1/keys", json={"name": "a"}).json()["key"]
    key_b = authed_client.post("/v1/keys", json={"name": "b"}).json()["key"]
    statuses = [_analyze(key_a, f"Subject: m{i}\n\nhello {i}").status_code for i in range(31)]
    assert statuses[:30] == [200] * 30
    assert statuses[30] == 429
    # A different key has its own bucket.
    assert _analyze(key_b, "Subject: other\n\nhello").status_code == 200


def test_server_to_server_call_without_origin_is_not_blocked(api_key):
    """Apps Script's UrlFetchApp sends no Origin header; CORS must not interfere."""
    resp = _analyze(api_key, "Subject: hi\n\nhello")
    assert resp.status_code == 200
    assert "access-control-allow-origin" not in {k.lower() for k in resp.headers}


# ---- persist: "if_not_clean" (the Gmail add-on's auto-analyze-on-open mode) ------------------


def _analyze_if_not_clean(key: str, raw: str):
    return _key_client(key).post("/v1/analyze/email", json={"raw_email": raw, "persist": "if_not_clean"})


def test_if_not_clean_with_a_malicious_sample_creates_a_case(api_key, load_eml, db_session):
    raw = load_eml("phishing_lookalike_paypal.eml").decode("utf-8")
    resp = _analyze_if_not_clean(api_key, raw)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert set(body) == CONTRACT_KEYS
    assert body["verdict"] == "malicious"
    assert db_session.query(Case).count() == 1
    # Same result as the default mode would have given.
    assert body == _analyze(api_key, raw).json()
    assert db_session.query(Case).count() == 1  # dedup still applies


def test_if_not_clean_with_a_clean_sample_returns_clean_and_saves_nothing(api_key, load_eml, db_session):
    raw = load_eml("benign_newsletter.eml").decode("utf-8")
    resp = _analyze_if_not_clean(api_key, raw)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert set(body) == CONTRACT_KEYS
    assert body["verdict"] == "clean"
    assert body["auth"] == {"spf": "pass", "dkim": "pass", "dmarc": "pass"}
    assert db_session.query(Case).count() == 0

    # Re-analyzing still saves nothing and returns the same result.
    assert _analyze_if_not_clean(api_key, raw).json() == body
    assert db_session.query(Case).count() == 0
    db_session.expire_all()
    assert db_session.query(ApiKey).one().last_used_at is not None


def test_clean_result_is_identical_with_or_without_persisting(api_key, load_eml, db_session):
    raw = load_eml("benign_newsletter.eml").decode("utf-8")
    skipped = _analyze_if_not_clean(api_key, raw).json()
    saved = _analyze(api_key, raw).json()  # default "always" still saves clean mail
    assert skipped == saved
    assert db_session.query(Case).count() == 1


def test_if_not_clean_returns_an_already_saved_case(api_key, load_eml, db_session):
    raw = load_eml("benign_newsletter.eml").decode("utf-8")
    saved = _analyze(api_key, raw).json()
    assert _analyze_if_not_clean(api_key, raw).json() == saved
    assert db_session.query(Case).count() == 1


@pytest.mark.parametrize("persist", ["never", "", None, 1])
def test_unknown_persist_value_is_422(api_key, persist):
    resp = _key_client(api_key).post("/v1/analyze/email", json={"raw_email": "Subject: hi\n\nhello", "persist": persist})
    assert resp.status_code == 422
