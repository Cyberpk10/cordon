"""Confirms an unhandled exception never reaches the client as a stack trace or any other
internal detail — app.main.create_app()'s catch-all `@app.exception_handler(Exception)`
logs the full exception server-side (via logger.exception) and returns a flat, generic JSON
body to the caller. FastAPI's own debug=False default (never overridden anywhere in this app)
already avoids a traceback in the response; this test is what actually proves that holds for
a real unhandled exception raised from inside a route, not just "FastAPI's default is probably
fine," and that the response is the deliberate JSON contract rather than Starlette's bare
text fallback.
"""

from __future__ import annotations

import logging

from fastapi.testclient import TestClient

import app.api.routes.auth as auth_routes
from app.main import app as fastapi_app


def _no_raise_client() -> TestClient:
    """TestClient defaults to raise_server_exceptions=True (convenient for debugging a test
    failure), which re-raises an unhandled exception straight into the test instead of
    letting Starlette's ServerErrorMiddleware convert it the way a real ASGI server (uvicorn)
    would. Disabling that here is what actually exercises the production error path — the
    registered `@app.exception_handler(Exception)` in app.main — rather than bypassing it.
    Reuses the shared `app` singleton (and whatever dependency_overrides the autouse
    tests/conftest.py fixtures already installed on it), just with a different TestClient
    wrapping it.
    """
    return TestClient(fastapi_app, raise_server_exceptions=False)


def test_unhandled_exception_returns_a_generic_500_with_no_internal_detail(monkeypatch, caplog):
    secret_detail = "boom: connection string postgresql://realuser:realpass@internal-host/db"

    def _boom(*args, **kwargs):
        raise RuntimeError(secret_detail)

    monkeypatch.setattr(auth_routes, "log_event", _boom)

    with caplog.at_level(logging.ERROR):
        response = _no_raise_client().post(
            "/api/auth/signup",
            json={
                "account_name": "Boom Co",
                "email": "boom@example.com",
                "password": "Str0ngTestPassw0rd!",
            },
        )

    assert response.status_code == 500
    body = response.json()
    assert body == {"detail": "Internal server error."}

    raw_text = response.text
    assert secret_detail not in raw_text
    assert "RuntimeError" not in raw_text
    assert "Traceback" not in raw_text
    assert "app/api/routes/auth.py" not in raw_text

    # The full detail must still reach the server's own logs — "generic to the client" must
    # not mean "nowhere," or an operator could never actually investigate the failure.
    # caplog.text includes each record's formatted exc_info (the traceback), which is where
    # the exception's own message actually lands — record.getMessage() alone is just the
    # logger.exception(...) call's own "Unhandled exception processing ..." format string.
    assert secret_detail in caplog.text


def test_security_headers_still_present_on_an_unhandled_exception_response(monkeypatch):
    def _boom(*args, **kwargs):
        raise RuntimeError("unexpected")

    monkeypatch.setattr(auth_routes, "log_event", _boom)

    response = _no_raise_client().post(
        "/api/auth/signup",
        json={
            "account_name": "Boom Co 2",
            "email": "boom2@example.com",
            "password": "Str0ngTestPassw0rd!",
        },
    )

    assert response.status_code == 500
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers.get("Cache-Control") == "no-store"
