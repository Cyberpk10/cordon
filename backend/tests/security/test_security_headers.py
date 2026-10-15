"""Confirms SecurityHeadersMiddleware (app.core.security_headers) actually lands on real
responses, including ones a route handler never gets to run for (a 401 from an auth
dependency, a 429 from the rate limiter) — the middleware is added last in
app.main.create_app() specifically so it wraps every other layer, and this is what proves
that placement holds rather than just asserting on the middleware class in isolation.
"""

from __future__ import annotations


def test_security_headers_present_on_a_plain_response(client):
    response = client.get("/health")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Referrer-Policy"] == "no-referrer"
    assert "Strict-Transport-Security" in response.headers
    assert "max-age=" in response.headers["Strict-Transport-Security"]
    assert "Permissions-Policy" in response.headers


def test_security_headers_present_on_a_401(client):
    response = client.get("/api/cases")
    assert response.status_code == 401
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["X-Content-Type-Options"] == "nosniff"


def test_security_headers_present_on_a_429_rate_limited_response(client):
    for _ in range(10):
        client.post("/api/auth/login", json={"email": "nobody@example.com", "password": "x"})
    response = client.post(
        "/api/auth/login", json={"email": "nobody@example.com", "password": "x"}
    )
    assert response.status_code == 429
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["Referrer-Policy"] == "no-referrer"


def test_auth_responses_are_not_cached(client):
    response = client.post(
        "/api/auth/signup",
        json={
            "account_name": "No Cache Co",
            "email": "nocache@example.com",
            "password": "Str0ngTestPassw0rd!",
        },
    )
    assert response.headers["Cache-Control"] == "no-store"


def test_non_auth_responses_are_not_forced_no_store(client):
    """Cache-Control: no-store is scoped to /api/auth — it shouldn't blanket every route,
    since that would defeat caching for genuinely cacheable, non-sensitive responses."""
    response = client.get("/health")
    assert response.headers.get("Cache-Control") != "no-store"
