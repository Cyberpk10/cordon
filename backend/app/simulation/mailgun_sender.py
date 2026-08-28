"""Outbound Mailgun sending for phishing-simulation email (M9 Stage 1). Distinct from
app.inbound.mailgun, which only ever verifies *inbound* webhook signatures — no outbound
sending code existed anywhere in this codebase before this module.

Failure contract, matching app.autonomy.graph_connector: `send_simulation_email` either
returns a `SimulationSendResult` describing a genuine outcome, or raises — callers infer
per-recipient success/failure from whether an exception was raised, not by inspecting a
possibly-ambiguous return value.

Every real send unconditionally carries the X-Cordon-Simulation/X-Cordon-Campaign-Id headers —
this is what marks the email as a Cordon simulation rather than a spoofed real sender, and is
asserted directly in tests.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Literal

import httpx

from app.core.config import settings

_SIMULATION_HEADER = "X-Cordon-Simulation"
_CAMPAIGN_HEADER = "X-Cordon-Campaign-Id"


@dataclass(frozen=True)
class SimulationSendResult:
    outcome: Literal["sent", "dry_run"]
    mailgun_message_id: str | None


def mailgun_is_configured() -> bool:
    return bool(settings.mailgun_api_key and settings.simulation_sending_domain)


def send_simulation_email(
    *,
    to_address: str,
    from_address: str,
    from_display_name: str,
    subject: str,
    html_body: str,
    text_body: str,
    campaign_id: uuid.UUID,
) -> SimulationSendResult:
    """Degrades to a dry run (no real network call) when Mailgun credentials or the
    simulation-sending domain are unconfigured — mirrors app.autonomy.connector_factory's
    graceful fallback, so a campaign can never accidentally reach a real mailbox from an
    unconfigured deployment."""
    if not mailgun_is_configured():
        return SimulationSendResult(outcome="dry_run", mailgun_message_id=None)

    response = httpx.post(
        f"{settings.mailgun_api_base_url}/{settings.simulation_sending_domain}/messages",
        auth=("api", settings.mailgun_api_key),
        data={
            "from": f"{from_display_name} <{from_address}>",
            "to": to_address,
            "subject": subject,
            "html": html_body,
            "text": text_body,
            f"h:{_SIMULATION_HEADER}": "true",
            f"h:{_CAMPAIGN_HEADER}": str(campaign_id),
            "o:tag": "cordon-simulation",
        },
        timeout=settings.mailgun_send_timeout_seconds,
    )
    if response.status_code >= 300:
        raise RuntimeError(f"Mailgun send failed: HTTP {response.status_code} — {response.text}")

    return SimulationSendResult(outcome="sent", mailgun_message_id=response.json().get("id"))
