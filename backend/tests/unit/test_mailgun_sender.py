"""Required test: every real Mailgun send must carry the X-Cordon-Simulation marker header
(and the campaign-id header) — this is what lets any recipient's mail system, or a future
Cordon-side scan, recognize the email as an authorized Cordon simulation rather than a
spoofed real sender. Also covers the dry-run fallback: with no Mailgun credentials
configured, no network call may be attempted at all.
"""

from __future__ import annotations

import uuid
from urllib.parse import parse_qs

import httpx
import pytest
import respx

from app.core.config import settings
from app.simulation.mailgun_sender import send_simulation_email


@pytest.fixture(autouse=True)
def _configured_mailgun(monkeypatch):
    monkeypatch.setattr(settings, "mailgun_api_key", "test-mailgun-key")
    monkeypatch.setattr(settings, "simulation_sending_domain", "sim.cordon.example")


def _send_url() -> str:
    return f"{settings.mailgun_api_base_url}/{settings.simulation_sending_domain}/messages"


def test_real_send_carries_the_simulation_marker_headers():
    campaign_id = uuid.uuid4()
    with respx.mock() as mock:
        route = mock.post(_send_url()).mock(
            return_value=httpx.Response(200, json={"id": "<mailgun-message-id>"})
        )

        result = send_simulation_email(
            to_address="alice@corp.example",
            from_address="it-support@sim.cordon.example",
            from_display_name="IT Support",
            subject="Test subject",
            html_body="<p>hi {tracking_url}</p>",
            text_body="hi",
            campaign_id=campaign_id,
        )

    assert result.outcome == "sent"
    assert result.mailgun_message_id == "<mailgun-message-id>"
    assert route.call_count == 1

    sent_body = parse_qs(route.calls[0].request.content.decode())
    assert sent_body["h:X-Cordon-Simulation"] == ["true"]
    assert sent_body["h:X-Cordon-Campaign-Id"] == [str(campaign_id)]


def test_send_failure_raises_and_never_returns_a_soft_failure():
    with respx.mock() as mock:
        mock.post(_send_url()).mock(return_value=httpx.Response(500, text="mailgun down"))

        with pytest.raises(RuntimeError):
            send_simulation_email(
                to_address="alice@corp.example",
                from_address="it-support@sim.cordon.example",
                from_display_name="IT Support",
                subject="Test subject",
                html_body="<p>hi</p>",
                text_body="hi",
                campaign_id=uuid.uuid4(),
            )


def test_unconfigured_mailgun_dry_runs_without_any_network_call(monkeypatch):
    monkeypatch.setattr(settings, "mailgun_api_key", "")
    monkeypatch.setattr(settings, "simulation_sending_domain", "")

    with respx.mock() as mock:
        # No routes registered at all — an accidental live call here would raise, since
        # respx.mock() rejects any unmocked request by default.
        result = send_simulation_email(
            to_address="alice@corp.example",
            from_address="it-support@dry-run.invalid",
            from_display_name="IT Support",
            subject="Test subject",
            html_body="<p>hi</p>",
            text_body="hi",
            campaign_id=uuid.uuid4(),
        )
        assert len(mock.calls) == 0

    assert result.outcome == "dry_run"
    assert result.mailgun_message_id is None
