"""Adversarial coverage for the phishing-simulation endpoint surface: every mutating/admin
endpoint must reject an unauthenticated caller, while GET /api/sim/track/{token} — the one
endpoint an anonymous trainee actually hits — must work with zero credentials, by design.
"""

from __future__ import annotations

import uuid


def test_verify_domain_rejects_unauthenticated(client):
    response = client.post("/api/sim/domains/verify", json={"domain": "corp.example.com"})
    assert response.status_code == 401


def test_create_campaign_rejects_unauthenticated(client):
    response = client.post(
        "/api/sim/campaigns",
        json={
            "name": "x",
            "template_id": "it_password_reset",
            "recipients": [{"email": "alice@corp.example.com"}],
        },
    )
    assert response.status_code == 401


def test_send_campaign_rejects_unauthenticated(client):
    response = client.post(
        f"/api/sim/campaigns/{uuid.uuid4()}/send", json={"authorization_accepted": True}
    )
    assert response.status_code == 401


def test_get_campaign_rejects_unauthenticated(client):
    response = client.get(f"/api/sim/campaigns/{uuid.uuid4()}")
    assert response.status_code == 401


def test_list_templates_rejects_unauthenticated(client):
    response = client.get("/api/sim/templates")
    assert response.status_code == 401


def test_track_endpoint_needs_no_authentication_by_design(client):
    """A nonexistent token still returns 404, not 401 — proving no auth dependency gates
    this route at all, which is the intended design (the caller is an anonymous trainee)."""
    response = client.get("/api/sim/track/some-token")
    assert response.status_code == 404
    assert response.status_code != 401
