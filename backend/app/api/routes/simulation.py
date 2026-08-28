"""Authorized phishing-simulation campaigns (M9 Stage 1) — sending security-awareness test
emails to an account's own employees, defensive tooling only.

Every guardrail below is enforced here, not just documented: `_verified_domains_for` gates
campaign creation so recipients may only be on domains this account has proven DNS control of
(`app.simulation.dns_check`); `send_campaign` refuses to send without an explicit, logged
admin authorization (`CampaignSendRequest.authorization_accepted`); outbound mail always goes
through `app.simulation.mailgun_sender`, which sends from a Cordon-owned domain and stamps
every message with the X-Cordon-Simulation marker header; and `track` (the public landing-page
endpoint) never reads a request body, so there is no code path here that could ever persist a
value a trainee typed into the fake login form — see app.db.models.SimulationRecipient's
docstring for why that's a structural property of the schema, not an application choice.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from app.auth.audit_log import log_event
from app.auth.dependencies import get_current_user, require_admin
from app.auth.rate_limit import limiter
from app.auth.security import generate_opaque_token, hash_token
from app.core.config import settings
from app.db.models import (
    SimulationCampaign,
    SimulationDomain,
    SimulationEvent,
    SimulationRecipient,
    User,
)
from app.db.session import get_db
from app.models.schemas import (
    CampaignCreateRequest,
    CampaignDetailResponse,
    CampaignRecipientSummary,
    CampaignSendRequest,
    DomainVerifyRequest,
    DomainVerifyResponse,
    SimulationCampaignStatus,
    SimulationDomainStatus,
    SimulationRecipientStatus,
    SimulationTemplateResponse,
    TemplateListResponse,
)
from app.simulation.dns_check import (
    domain_is_verified_by,
    verification_record_name,
    verification_record_value,
)
from app.simulation.landing_page import render_invalid_link_page, render_teaching_page
from app.simulation.mailgun_sender import mailgun_is_configured, send_simulation_email
from app.simulation.policy import advance_status
from app.simulation.templates import TEMPLATES

router = APIRouter(prefix="/api/sim", tags=["simulation"])

_TRACK_RATE_LIMIT = "60/minute"

_DOMAIN_RE = re.compile(
    r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$"
)
_EMAIL_RE = re.compile(r"^[^@\s]+@([^@\s]+\.[^@\s]+)$")


def _client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def _normalize_domain(raw: str) -> str:
    return raw.strip().lower()


def _normalize_email(raw: str) -> str:
    return raw.strip().lower()


def _email_domain(email: str) -> str | None:
    match = _EMAIL_RE.match(email)
    return match.group(1) if match else None


def _to_recipient_summary(
    recipient: SimulationRecipient, *, dry_run_tracking_urls: dict[uuid.UUID, str]
) -> CampaignRecipientSummary:
    return CampaignRecipientSummary(
        id=recipient.id,
        email=recipient.email,
        status=SimulationRecipientStatus(recipient.status),
        sent_at=recipient.sent_at,
        clicked_at=recipient.clicked_at,
        click_count=recipient.click_count,
        submitted_at=recipient.submitted_at,
        submit_count=recipient.submit_count,
        dry_run_tracking_url=dry_run_tracking_urls.get(recipient.id),
    )


def _to_campaign_detail(
    campaign: SimulationCampaign, *, dry_run_tracking_urls: dict[uuid.UUID, str] | None = None
) -> CampaignDetailResponse:
    urls = dry_run_tracking_urls or {}
    return CampaignDetailResponse(
        id=campaign.id,
        name=campaign.name,
        template_id=campaign.template_id,
        status=SimulationCampaignStatus(campaign.status),
        dry_run=campaign.dry_run,
        from_address=campaign.from_address,
        created_at=campaign.created_at,
        created_by_user_id=campaign.created_by_user_id,
        authorized_by_user_id=campaign.authorized_by_user_id,
        authorized_at=campaign.authorized_at,
        sent_at=campaign.sent_at,
        recipients=[
            _to_recipient_summary(r, dry_run_tracking_urls=urls) for r in campaign.recipients
        ],
    )


@router.post("/domains/verify", response_model=DomainVerifyResponse)
async def verify_domain(
    body: DomainVerifyRequest,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> DomainVerifyResponse:
    domain = _normalize_domain(body.domain)
    if not domain or not _DOMAIN_RE.match(domain):
        raise HTTPException(status_code=400, detail="Not a valid domain.")

    now = datetime.now(timezone.utc)
    row = (
        db.query(SimulationDomain)
        .filter(SimulationDomain.account_id == current_user.account_id, SimulationDomain.domain == domain)
        .first()
    )
    if row is None:
        row = SimulationDomain(
            account_id=current_user.account_id,
            domain=domain,
            verification_token=generate_opaque_token(),
            status="pending",
        )
        db.add(row)
        db.commit()
        db.refresh(row)
    elif row.status == "pending" and domain_is_verified_by(row.verification_token, domain):
        row.status = "verified"
        row.verified_at = now
        log_event(
            db,
            event_type="simulation_domain_verified",
            account_id=current_user.account_id,
            user_id=current_user.id,
            detail={"domain": domain},
        )
        db.commit()
        db.refresh(row)

    return DomainVerifyResponse(
        domain=row.domain,
        status=SimulationDomainStatus(row.status),
        verification_record_name=verification_record_name(row.domain),
        verification_record_value=verification_record_value(row.verification_token),
        verified_at=row.verified_at,
        checked_at=now,
    )


@router.get("/templates", response_model=TemplateListResponse)
async def list_templates(current_user: User = Depends(get_current_user)) -> TemplateListResponse:
    return TemplateListResponse(
        items=[
            SimulationTemplateResponse(
                id=t.id,
                name=t.name,
                category=t.category,
                subject=t.subject,
                sender_display_name=t.sender_display_name,
                landing_page_headline=t.landing_page_headline,
                landing_page_teaching_points=t.landing_page_teaching_points,
                has_fake_login_form=t.has_fake_login_form,
            )
            for t in TEMPLATES.values()
        ]
    )


@router.post("/campaigns", response_model=CampaignDetailResponse, status_code=201)
async def create_campaign(
    body: CampaignCreateRequest,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> CampaignDetailResponse:
    if body.template_id not in TEMPLATES:
        raise HTTPException(status_code=400, detail=f"Unknown template_id: {body.template_id}")

    normalized: dict[str, str] = {}
    for entry in body.recipients:
        email = _normalize_email(entry.email)
        if _email_domain(email) is None:
            raise HTTPException(status_code=422, detail=f"Not a valid email address: {entry.email}")
        normalized[email] = email  # dedupe case-insensitively

    recipient_emails = list(normalized.values())
    domains = {_email_domain(e) for e in recipient_emails}

    verified_domains = {
        row.domain
        for row in db.query(SimulationDomain).filter(
            SimulationDomain.account_id == current_user.account_id,
            SimulationDomain.domain.in_(domains),
            SimulationDomain.status == "verified",
        )
    }
    unverified = sorted(domains - verified_domains)
    if unverified:
        raise HTTPException(
            status_code=400,
            detail=(
                "The following domains are not verified for this account: "
                + ", ".join(unverified)
            ),
        )

    campaign = SimulationCampaign(
        account_id=current_user.account_id,
        name=body.name,
        template_id=body.template_id,
        status="draft",
        created_by_user_id=current_user.id,
    )
    db.add(campaign)
    db.flush()

    for email in recipient_emails:
        db.add(
            SimulationRecipient(
                account_id=current_user.account_id,
                campaign_id=campaign.id,
                email=email,
                status="pending",
            )
        )

    log_event(
        db,
        event_type="simulation_campaign_created",
        account_id=current_user.account_id,
        user_id=current_user.id,
        detail={
            "campaign_id": str(campaign.id),
            "template_id": body.template_id,
            "recipient_count": len(recipient_emails),
        },
    )
    db.commit()
    db.refresh(campaign)
    return _to_campaign_detail(campaign)


@router.get("/campaigns/{campaign_id}", response_model=CampaignDetailResponse)
async def get_campaign(
    campaign_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> CampaignDetailResponse:
    campaign = (
        db.query(SimulationCampaign)
        .filter(SimulationCampaign.id == campaign_id, SimulationCampaign.account_id == current_user.account_id)
        .first()
    )
    if campaign is None:
        raise HTTPException(status_code=404, detail="Campaign not found.")
    # dry_run_tracking_url is only ever populated in the response returned directly from
    # POST .../send (the one moment the raw, pre-hash token is in memory) — a later GET here
    # can never reconstruct it, since only the SHA-256 hash is persisted.
    return _to_campaign_detail(campaign)


@router.post("/campaigns/{campaign_id}/send", response_model=CampaignDetailResponse)
async def send_campaign(
    campaign_id: uuid.UUID,
    body: CampaignSendRequest,
    request: Request,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> CampaignDetailResponse:
    campaign = (
        db.query(SimulationCampaign)
        .filter(SimulationCampaign.id == campaign_id, SimulationCampaign.account_id == current_user.account_id)
        .first()
    )
    if campaign is None:
        raise HTTPException(status_code=404, detail="Campaign not found.")

    if not settings.enable_phishing_simulation:
        raise HTTPException(status_code=503, detail="Phishing simulation is not enabled.")

    if campaign.status != "draft":
        raise HTTPException(status_code=409, detail=f"Campaign is already '{campaign.status}'.")

    if not body.authorization_accepted:
        raise HTTPException(
            status_code=400,
            detail="Sending requires explicitly accepting the authorization statement.",
        )

    # Authorize first, durably, before any network I/O — this fact survives even if sending
    # subsequently fails.
    now = datetime.now(timezone.utc)
    campaign.authorized_by_user_id = current_user.id
    campaign.authorized_at = now
    campaign.status = "authorized"
    log_event(
        db,
        event_type="simulation_campaign_authorized",
        account_id=current_user.account_id,
        user_id=current_user.id,
        detail={"campaign_id": str(campaign.id)},
    )
    db.commit()

    campaign.status = "sending"
    dry_run = not mailgun_is_configured()
    if not dry_run and not settings.simulation_tracking_base_url:
        campaign.status = "send_failed"
        db.commit()
        raise HTTPException(
            status_code=503, detail="Simulation tracking URL is not configured for sending."
        )

    template = TEMPLATES[campaign.template_id]
    from_address = f"{template.sender_local_part}@{settings.simulation_sending_domain or 'dry-run.invalid'}"
    campaign.from_address = from_address

    if settings.simulation_tracking_base_url:
        tracking_base = settings.simulation_tracking_base_url.rstrip("/")
    else:
        tracking_base = str(request.base_url).rstrip("/")

    dry_run_tracking_urls: dict[uuid.UUID, str] = {}
    for recipient in campaign.recipients:
        if recipient.status != "pending":
            continue

        raw_token = generate_opaque_token()
        recipient.token_hash = hash_token(raw_token)
        tracking_url = f"{tracking_base}/api/sim/track/{raw_token}"

        try:
            result = send_simulation_email(
                to_address=recipient.email,
                from_address=from_address,
                from_display_name=template.sender_display_name,
                subject=template.subject,
                html_body=template.html_body_template.format(tracking_url=tracking_url),
                text_body=template.text_body_template.format(tracking_url=tracking_url),
                campaign_id=campaign.id,
            )
        except Exception as exc:  # noqa: BLE001 — recorded per-recipient, never aborts the batch
            recipient.status = "send_failed"
            recipient.send_error = str(exc)
            continue

        recipient.status = "sent"
        recipient.sent_at = datetime.now(timezone.utc)
        recipient.mailgun_message_id = result.mailgun_message_id
        if result.outcome == "dry_run":
            dry_run_tracking_urls[recipient.id] = tracking_url

    any_sent = any(r.status == "sent" for r in campaign.recipients)
    campaign.status = "sent" if any_sent else "send_failed"
    campaign.dry_run = dry_run
    campaign.sent_at = datetime.now(timezone.utc)

    log_event(
        db,
        event_type="simulation_campaign_sent",
        account_id=current_user.account_id,
        user_id=current_user.id,
        detail={
            "campaign_id": str(campaign.id),
            "dry_run": dry_run,
            "sent_count": sum(1 for r in campaign.recipients if r.status == "sent"),
            "failed_count": sum(1 for r in campaign.recipients if r.status == "send_failed"),
        },
    )
    db.commit()
    db.refresh(campaign)
    return _to_campaign_detail(campaign, dry_run_tracking_urls=dry_run_tracking_urls)


@router.get("/track/{token}", response_class=HTMLResponse)
@limiter.limit(_TRACK_RATE_LIMIT)
async def track(
    request: Request,
    token: str,
    event: str | None = Query(default=None),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    """Public — no auth. The recipient clicking this link is an anonymous person, not a
    logged-in Cordon user; the opaque token itself is the only thing identifying them.
    Deliberately takes no request body (`event` is the only thing besides the path token) —
    see the module docstring for why that's what makes credential capture structurally
    impossible here, not just an application-level choice not to read one."""
    recipient = (
        db.query(SimulationRecipient).filter(SimulationRecipient.token_hash == hash_token(token)).first()
    )
    if recipient is None:
        return HTMLResponse(render_invalid_link_page(), status_code=404)

    kind = "submit" if event == "submit" else "click"
    now = datetime.now(timezone.utc)
    recipient.status = advance_status(recipient.status, kind)
    if kind == "click":
        recipient.clicked_at = recipient.clicked_at or now
        recipient.click_count += 1
    else:
        recipient.submitted_at = recipient.submitted_at or now
        recipient.submit_count += 1

    db.add(
        SimulationEvent(
            account_id=recipient.account_id,
            campaign_id=recipient.campaign_id,
            recipient_id=recipient.id,
            event_type=kind,
            occurred_at=now,
            ip_address=_client_ip(request),
        )
    )
    db.commit()

    template = TEMPLATES[recipient.campaign.template_id]
    html = render_teaching_page(
        template,
        show_fake_form=(kind == "click" and template.has_fake_login_form),
        already_submitted=(kind == "submit"),
    )
    return HTMLResponse(html)
