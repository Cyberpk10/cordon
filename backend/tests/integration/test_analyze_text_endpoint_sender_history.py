from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from app.db.models import Case, TrustedVendorDomain

_RAW_TEMPLATE = """From: "Acme Vendor" <billing@acme-vendor.example>
To: ap-team@ourcompany.example
Subject: {subject}
Date: Mon, 24 Aug 2026 10:05:00 +0000
Authentication-Results: mx.ourcompany.example; spf=pass smtp.mailfrom=acme-vendor.example; dkim=pass header.d=acme-vendor.example; dmarc=pass header.from=acme-vendor.example
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

{body}
"""


def _seed_prior_cases(db_session, account_id, from_addr: str, count: int, span_days: int) -> None:
    now = datetime.now(timezone.utc)
    for i in range(count):
        db_session.add(
            Case(
                id=uuid.uuid4(),
                account_id=account_id,
                filename=f"prior-{i}.eml",
                verdict="safe",
                score=0,
                from_addr=from_addr,
                to_addresses=[],
                indicators=[],
                framework_mappings={},
                created_at=now - timedelta(days=span_days - i),
            )
        )
    db_session.commit()


def test_established_sender_history_suppresses_first_contact(
    authed_client, db_session, test_account
):
    _seed_prior_cases(db_session, test_account.account.id, "billing@acme-vendor.example", 4, 10)

    raw = _RAW_TEMPLATE.format(subject="Invoice", body="As discussed, invoice attached.")
    response = authed_client.post("/api/analyze/text", json={"raw_text": raw})
    ids = {i["id"] for i in response.json()["indicators"]}
    assert "FIRST_CONTACT_SENDER" not in ids
    assert "UNKNOWN_VENDOR_CLAIM" not in ids


def test_lookalike_of_established_sender_flags_via_full_pipeline(
    authed_client, db_session, test_account
):
    _seed_prior_cases(db_session, test_account.account.id, "billing@acme-vendor.example", 4, 10)

    raw = _RAW_TEMPLATE.replace("acme-vendor.example", "acme-vend0r.example").format(
        subject="Invoice", body="As discussed, invoice attached."
    )
    response = authed_client.post("/api/analyze/text", json={"raw_text": raw})
    ids = {i["id"] for i in response.json()["indicators"]}
    assert "LOOKALIKE_OF_KNOWN_SENDER" in ids


def test_first_analysis_ever_for_account_does_not_flip_verdict_on_first_contact_alone(
    authed_client,
):
    raw = _RAW_TEMPLATE.format(subject="Hi", body="Just reaching out, no rush.")
    response = authed_client.post("/api/analyze/text", json={"raw_text": raw})
    assert response.json()["verdict"] == "safe"


def test_trusted_vendor_domain_suppresses_first_contact_end_to_end(authed_client):
    authed_client.post("/api/vendor-domains", json={"domain": "acme-vendor.example"})

    raw = _RAW_TEMPLATE.format(subject="Hi", body="Just reaching out, no rush.")
    response = authed_client.post("/api/analyze/text", json={"raw_text": raw})
    ids = {i["id"] for i in response.json()["indicators"]}
    assert "FIRST_CONTACT_SENDER" not in ids


def test_evasive_vendor_impersonation_now_flips_to_non_safe(authed_client):
    """The literal shape of phase-2 scenario 5 (uncurated B2B vendor domain, no urgency/
    credential phrase-bank matches, vendor-relationship claim, first contact) — must now
    raise a non-safe verdict via FIRST_CONTACT_SENDER + UNKNOWN_VENDOR_CLAIM."""
    raw = """From: "Meridian Compliance Partners" <notifications@meridian-compliance-portal.example>
To: target-employee@ourcompany.example
Subject: Your Q3 vendor access review is ready
Date: Wed, 26 Aug 2026 09:40:00 +0000
Authentication-Results: mx.ourcompany.example; spf=pass smtp.mailfrom=meridian-compliance-portal.example; dkim=pass header.d=meridian-compliance-portal.example; dmarc=pass header.from=meridian-compliance-portal.example
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

Meridian handles the quarterly vendor access reviews for a few of our partner
organizations, and yours is part of this cycle. It's a short form, mostly
checking which systems you still need access to.

You can find it here: https://meridian-compliance-portal.example/reviews/q3-2026
"""
    response = authed_client.post("/api/analyze/text", json={"raw_text": raw})
    body = response.json()
    ids = {i["id"] for i in body["indicators"]}
    assert {"FIRST_CONTACT_SENDER", "UNKNOWN_VENDOR_CLAIM"} <= ids
    assert body["verdict"] != "safe"
