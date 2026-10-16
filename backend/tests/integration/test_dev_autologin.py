"""POST /api/auth/dev-login - local/dev-only, no-credential sign-in. The hard safety property
under test here is the double gate (app.api.routes.auth._ensure_dev_autologin_allowed): the
endpoint must 404 unless settings.enable_dev_autologin is explicitly on AND
settings.environment is anything other than "production" - and the production check must win
even if the opt-in flag is also on, since that's the one combination that must never, under
any configuration mistake, hand out a free admin session on a real deployment.
"""

from __future__ import annotations

from app.core.config import settings


def _enable(monkeypatch, *, environment: str = "development") -> None:
    monkeypatch.setattr(settings, "enable_dev_autologin", True)
    monkeypatch.setattr(settings, "environment", environment)


def test_dev_login_disabled_by_default_returns_404(client):
    """conftest.py doesn't pin this flag the way it pins enable_llm_reasoning/enable_ml_
    classifier - this test is what actually proves the real, un-monkeypatched default is
    off."""
    response = client.post("/api/auth/dev-login")
    assert response.status_code == 404


def test_dev_login_404s_in_production_even_with_the_flag_on(client, monkeypatch):
    """The critical safety test: the production check wins regardless of the opt-in flag."""
    _enable(monkeypatch, environment="production")
    response = client.post("/api/auth/dev-login")
    assert response.status_code == 404


def test_dev_login_404s_with_flag_off_even_in_development(client, monkeypatch):
    monkeypatch.setattr(settings, "enable_dev_autologin", False)
    monkeypatch.setattr(settings, "environment", "development")
    response = client.post("/api/auth/dev-login")
    assert response.status_code == 404


def test_dev_login_succeeds_when_enabled_outside_production(client, monkeypatch):
    _enable(monkeypatch)
    response = client.post("/api/auth/dev-login")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["token_type"] == "bearer"
    assert body["access_token"]
    assert body["refresh_token"]
    assert body["user"]["email"] == "dev-admin@cordon.local"
    assert body["user"]["role"] == "admin"


def test_dev_login_returned_token_is_actually_usable(client, monkeypatch):
    _enable(monkeypatch)
    body = client.post("/api/auth/dev-login").json()
    response = client.get(
        "/api/auth/me", headers={"Authorization": f"Bearer {body['access_token']}"}
    )
    assert response.status_code == 200
    assert response.json()["email"] == "dev-admin@cordon.local"


def test_dev_login_is_idempotent_same_account_every_call(client, monkeypatch):
    _enable(monkeypatch)
    first = client.post("/api/auth/dev-login").json()
    second = client.post("/api/auth/dev-login").json()
    assert first["user"]["id"] == second["user"]["id"]
    assert first["user"]["account_id"] == second["user"]["account_id"]


def test_dev_login_seeded_account_has_no_usable_password(client, monkeypatch):
    """The seeded dev-admin's password_hash is random and never revealed - confirms it
    can't be logged into via the real, credentialed /login endpoint by guessing a common
    password."""
    _enable(monkeypatch)
    client.post("/api/auth/dev-login")  # seed the account
    response = client.post(
        "/api/auth/login",
        json={"email": "dev-admin@cordon.local", "password": "password123"},
    )
    assert response.status_code == 401
