from __future__ import annotations

import uuid

from app.db.models import TrustedVendorDomain


def test_add_and_list_vendor_domain(authed_client):
    response = authed_client.post(
        "/api/vendor-domains", json={"domain": "Northbridge-Logistics.example", "label": "Northbridge"}
    )
    assert response.status_code == 201
    body = response.json()
    assert body["domain"] == "northbridge-logistics.example"
    assert body["label"] == "Northbridge"

    listing = authed_client.get("/api/vendor-domains")
    assert listing.status_code == 200
    assert len(listing.json()["items"]) == 1


def test_add_requires_admin(analyst_authed_client):
    response = analyst_authed_client.post(
        "/api/vendor-domains", json={"domain": "vendor.example"}
    )
    assert response.status_code == 403


def test_add_duplicate_domain_conflicts(authed_client):
    authed_client.post("/api/vendor-domains", json={"domain": "vendor.example"})
    response = authed_client.post("/api/vendor-domains", json={"domain": "vendor.example"})
    assert response.status_code == 409


def test_delete_requires_admin(analyst_authed_client, authed_client):
    created = authed_client.post("/api/vendor-domains", json={"domain": "vendor.example"})
    vendor_id = created.json()["id"]

    response = analyst_authed_client.delete(f"/api/vendor-domains/{vendor_id}")
    assert response.status_code == 403


def test_delete_removes_domain(authed_client):
    created = authed_client.post("/api/vendor-domains", json={"domain": "vendor.example"})
    vendor_id = created.json()["id"]

    response = authed_client.delete(f"/api/vendor-domains/{vendor_id}")
    assert response.status_code == 204

    listing = authed_client.get("/api/vendor-domains")
    assert listing.json()["items"] == []


def test_other_account_cannot_see_or_delete_vendor_domain(
    authed_client, other_account_authed_client, db_session
):
    created = authed_client.post("/api/vendor-domains", json={"domain": "vendor.example"})
    vendor_id = created.json()["id"]

    other_listing = other_account_authed_client.get("/api/vendor-domains")
    assert other_listing.json()["items"] == []

    delete_response = other_account_authed_client.delete(f"/api/vendor-domains/{vendor_id}")
    assert delete_response.status_code == 404

    assert db_session.query(TrustedVendorDomain).filter(
        TrustedVendorDomain.id == uuid.UUID(vendor_id)
    ).count() == 1
