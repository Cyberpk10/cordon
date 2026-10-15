"""Confirms /docs, /redoc, and /openapi.json are only ever reachable outside production.

app.main.create_app() reads settings.environment once, at construction time, to decide
docs_url/redoc_url/openapi_url — a factory function (not just the module-level `app`
singleton) specifically so this can be exercised under both environments the same way every
other settings-driven behavior in this app is tested: monkeypatch settings.environment, build
a fresh app, assert. The shared `client` fixture (tests/conftest.py) always exercises the
default, non-production app and is left untouched by this file.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.core.config import settings
from app.main import create_app


@pytest.fixture()
def production_client(monkeypatch) -> TestClient:
    monkeypatch.setattr(settings, "environment", "production")
    return TestClient(create_app())


@pytest.fixture()
def dev_client(monkeypatch) -> TestClient:
    monkeypatch.setattr(settings, "environment", "development")
    return TestClient(create_app())


@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json"])
def test_docs_routes_404_in_production(production_client, path):
    response = production_client.get(path)
    assert response.status_code == 404


@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json"])
def test_docs_routes_available_outside_production(dev_client, path):
    response = dev_client.get(path)
    assert response.status_code == 200
