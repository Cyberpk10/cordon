"""Account-level brute-force lockout (app.api.routes.auth::login, app.db.models.User.
failed_login_attempts/locked_until) — a second, independent layer on top of the per-IP
AUTH_RATE_LIMIT in app.auth.rate_limit. The per-IP limit alone doesn't stop a password-spray
attack that rotates source IPs while hammering the same account; this closes that gap.
Defaults: settings.account_lockout_threshold=5 consecutive failures,
settings.account_lockout_duration_minutes=15 — conservative enough that a real user fumbling
their password a couple of times is never affected, and self-clearing so no cleanup job or
admin action is needed to lift it.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from app.core.config import settings
from app.db.models import User

_STRONG_PASSWORD = "Str0ngTestPassw0rd!"
_EMAIL = "lockout-target@example.com"


def _signup(client, email=_EMAIL, password=_STRONG_PASSWORD):
    response = client.post(
        "/api/auth/signup",
        json={"account_name": "Lockout Co", "email": email, "password": password},
    )
    assert response.status_code == 200, response.text
    return response.json()


def _fail_login(client, email=_EMAIL):
    return client.post("/api/auth/login", json={"email": email, "password": "WrongPassword!"})


def test_account_locks_after_threshold_consecutive_failed_logins(client):
    _signup(client)

    for _ in range(settings.account_lockout_threshold):
        response = _fail_login(client)
        assert response.status_code == 401

    # Even the CORRECT password is now rejected — the lockout blocks the attempt before the
    # password is ever checked.
    locked_response = client.post(
        "/api/auth/login", json={"email": _EMAIL, "password": _STRONG_PASSWORD}
    )
    assert locked_response.status_code == 429
    assert "too many" in locked_response.json()["detail"].lower()


def test_fewer_than_threshold_failures_do_not_lock_the_account(client):
    _signup(client, email="under-threshold@example.com")

    for _ in range(settings.account_lockout_threshold - 1):
        response = _fail_login(client, email="under-threshold@example.com")
        assert response.status_code == 401

    # Still under threshold — the correct password must still work.
    success = client.post(
        "/api/auth/login",
        json={"email": "under-threshold@example.com", "password": _STRONG_PASSWORD},
    )
    assert success.status_code == 200


def test_successful_login_resets_the_failed_attempt_counter(client, db_session):
    _signup(client, email="resets-counter@example.com")

    for _ in range(settings.account_lockout_threshold - 1):
        _fail_login(client, email="resets-counter@example.com")

    success = client.post(
        "/api/auth/login",
        json={"email": "resets-counter@example.com", "password": _STRONG_PASSWORD},
    )
    assert success.status_code == 200

    user = db_session.query(User).filter(User.email == "resets-counter@example.com").first()
    assert user.failed_login_attempts == 0
    assert user.locked_until is None

    # A couple more failures right after a success must NOT lock the account — proves the
    # counter was reset to 0, not just decremented (which would lock far sooner than a fresh
    # threshold-many failures). Kept well under AUTH_RATE_LIMIT (10/minute) alongside the
    # requests already made above.
    for _ in range(2):
        response = _fail_login(client, email="resets-counter@example.com")
        assert response.status_code == 401

    still_unlocked = client.post(
        "/api/auth/login",
        json={"email": "resets-counter@example.com", "password": _STRONG_PASSWORD},
    )
    assert still_unlocked.status_code == 200


def test_lockout_self_clears_once_locked_until_is_in_the_past(client, db_session):
    _signup(client, email="self-clears@example.com")

    for _ in range(settings.account_lockout_threshold):
        _fail_login(client, email="self-clears@example.com")

    user = db_session.query(User).filter(User.email == "self-clears@example.com").first()
    assert user.locked_until is not None

    # Simulate the lockout window having already elapsed — no cleanup job exists or should
    # be needed; the next login attempt itself clears it.
    user.locked_until = datetime.utcnow() - timedelta(seconds=1)
    db_session.commit()

    response = client.post(
        "/api/auth/login",
        json={"email": "self-clears@example.com", "password": _STRONG_PASSWORD},
    )
    assert response.status_code == 200

    db_session.refresh(user)
    assert user.locked_until is None
    assert user.failed_login_attempts == 0


def test_lockout_is_scoped_to_the_targeted_account_only(client):
    _signup(client, email="victim@example.com")
    _signup(client, email="bystander@example.com")

    for _ in range(settings.account_lockout_threshold):
        _fail_login(client, email="victim@example.com")

    bystander_login = client.post(
        "/api/auth/login", json={"email": "bystander@example.com", "password": _STRONG_PASSWORD}
    )
    assert bystander_login.status_code == 200


def test_nonexistent_email_never_locks_and_stays_generic(client):
    """Login attempts against an email with no account must never 429 — there's no User row
    to attach a lockout counter to, and a distinct status code here would let an attacker
    enumerate which emails exist at all."""
    for _ in range(settings.account_lockout_threshold + 2):
        response = client.post(
            "/api/auth/login", json={"email": "never-signed-up@example.com", "password": "x"}
        )
        assert response.status_code == 401
