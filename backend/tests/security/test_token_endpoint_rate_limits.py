"""Confirms AUTH_RATE_LIMIT (10/minute per IP) covers the token-adjacent endpoints added in
the Stage 5 security-hardening pass — /refresh and /password-reset/confirm — not just
login/signup/password-reset-request/invite-accept, which tests/integration/
test_auth_endpoints.py and tests/security/test_rate_limit_abuse.py already cover. Both
endpoints take an opaque, unguessable token, so the realistic attack here is a flood of
guesses against the token itself; the IP-level cap bounds that regardless of how many
distinct (invalid) tokens are tried.
"""

from __future__ import annotations


def test_refresh_endpoint_rate_limited_after_ten_attempts_per_minute(client):
    for _ in range(10):
        response = client.post("/api/auth/refresh", json={"refresh_token": "not-a-real-token"})
        assert response.status_code == 401

    eleventh = client.post("/api/auth/refresh", json={"refresh_token": "not-a-real-token"})
    assert eleventh.status_code == 429


def test_password_reset_confirm_rate_limited_after_ten_attempts_per_minute(client):
    for _ in range(10):
        response = client.post(
            "/api/auth/password-reset/confirm",
            json={"token": "not-a-real-token", "new_password": "AnotherStr0ngPassw0rd!"},
        )
        assert response.status_code == 400

    eleventh = client.post(
        "/api/auth/password-reset/confirm",
        json={"token": "not-a-real-token", "new_password": "AnotherStr0ngPassw0rd!"},
    )
    assert eleventh.status_code == 429
