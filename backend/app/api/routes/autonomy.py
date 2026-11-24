"""Autonomy policy management, the kill switch, the audit log, and undo (M6 Stage 1).

Defensive containment only. Nothing in this module executes an action directly — that only
ever happens inside app.autonomy.executor.execute_if_authorized, itself only reachable from
the playbook-fetch wiring in app.api.routes.remediation. This module is the read/manage
surface: inspect and configure the policy, halt everything, browse what happened and why,
undo a reversible action, and (M6 Stage 2) connect an account's own Microsoft 365 tenant so
those actions can be real instead of simulated. Requires auth; scoped to the authenticated
user's account (M8 Stage 2) — policy view/actions/reverse are available to any account member,
but changing the policy, pulling the kill switch, or connecting Microsoft 365 is admin-only
and audit-logged.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from app.auth.audit_log import log_event
from app.auth.dependencies import get_current_user, require_admin
from app.autonomy.connector_factory import get_connector_for_account
from app.autonomy import runner
from app.autonomy.executor import reverse_action
from app.autonomy.store import get_or_create_policy_row
from app.db.models import AutonomyAction, AutonomyPolicy, CordonListEntry, GraphIntegration, Label, User
from app.db.session import get_db
from app.models.schemas import (
    CordonListEntryResponse,
    KillSwitchRequest,
    KillSwitchResponse,
    ShadowSummaryResponse,
    ShadowSummaryRow,
    AutonomyActionListResponse,
    AutonomyActionResponse,
    AutonomyHaltResponse,
    AutonomyPolicyRequest,
    AutonomyPolicyResponse,
    AutonomyPolicyRuleSchema,
    GraphIntegrationRequest,
    GraphIntegrationResponse,
)

router = APIRouter(prefix="/api/autonomy", tags=["autonomy"])


def _client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def _to_policy_response(row: AutonomyPolicy) -> AutonomyPolicyResponse:
    return AutonomyPolicyResponse(
        account_id=row.account_id,
        level=row.level,
        rules=[AutonomyPolicyRuleSchema(**rule) for rule in row.rules],
        exclusions=row.exclusions,
        blast_radius_limit=row.blast_radius_limit,
        blast_radius_window_minutes=row.blast_radius_window_minutes,
        halted_at=row.halted_at,
        updated_at=row.updated_at,
        tier=row.tier,
        shadow_mode=row.shadow_mode,
        kill_switch=row.kill_switch,
    )


@router.get("/policy", response_model=AutonomyPolicyResponse)
async def get_policy(
    db: Session = Depends(get_db), current_user: User = Depends(get_current_user)
) -> AutonomyPolicyResponse:
    row = get_or_create_policy_row(db, current_user.account_id)
    return _to_policy_response(row)


@router.put("/policy", response_model=AutonomyPolicyResponse)
async def put_policy(
    body: AutonomyPolicyRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> AutonomyPolicyResponse:
    row = get_or_create_policy_row(db, current_user.account_id)

    if body.tier is not None:
        row.tier = body.tier.value
    if body.shadow_mode is not None:
        row.shadow_mode = body.shadow_mode
    if body.level is not None:
        row.level = body.level.value
    if body.rules is not None:
        row.rules = [rule.model_dump(mode="json") for rule in body.rules]
    row.exclusions = body.exclusions
    row.blast_radius_limit = body.blast_radius_limit
    row.blast_radius_window_minutes = body.blast_radius_window_minutes

    log_event(
        db,
        event_type="autonomy_policy_updated",
        account_id=current_user.account_id,
        user_id=current_user.id,
        detail={"tier": row.tier, "shadow_mode": row.shadow_mode, "level": row.level},
        ip_address=_client_ip(request),
    )

    db.commit()
    db.refresh(row)
    return _to_policy_response(row)


@router.post("/halt", response_model=AutonomyHaltResponse)
async def halt(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> AutonomyHaltResponse:
    """The kill switch: drops the account to L0 and stops pending actions — every
    AutonomyAction row currently `status="pending_approval"` for this account is flipped to
    `status="halted"` so it no longer lingers as actionable."""
    row = get_or_create_policy_row(db, current_user.account_id)

    now = datetime.now(timezone.utc)
    row.level = "L0"
    row.halted_at = now
    row.kill_switch = True  # D5: /halt is the kill switch's "on"

    halted_count = (
        db.query(AutonomyAction)
        .filter(
            AutonomyAction.account_id == current_user.account_id,
            AutonomyAction.status == "pending_approval",
        )
        .update({"status": "halted"}, synchronize_session=False)
    )

    log_event(
        db,
        event_type="autonomy_halted",
        account_id=current_user.account_id,
        user_id=current_user.id,
        detail={"halted_pending_count": halted_count},
        ip_address=_client_ip(request),
    )

    db.commit()
    db.refresh(row)

    return AutonomyHaltResponse(
        account_id=current_user.account_id,
        level=row.level,
        halted_at=row.halted_at,
        halted_pending_count=halted_count,
    )


@router.get("/actions", response_model=AutonomyActionListResponse)
async def list_actions(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    case_id: UUID | None = None,
    incident_id: UUID | None = None,
    action_type: str | None = None,
    decision: str | None = None,
    status: str | None = None,
    date_from: datetime | None = None,
    date_to: datetime | None = None,
) -> AutonomyActionListResponse:
    """The filterable audit log — this doubles as the compliance-evidence export; every
    decision (auto_execute, require_approval, AND skip) is a row here, not just executed
    ones."""
    query = db.query(AutonomyAction).filter(AutonomyAction.account_id == current_user.account_id)

    if case_id is not None:
        query = query.filter(AutonomyAction.case_id == case_id)
    if incident_id is not None:
        query = query.filter(AutonomyAction.incident_id == incident_id)
    if action_type is not None:
        query = query.filter(AutonomyAction.action_type == action_type)
    if decision is not None:
        query = query.filter(AutonomyAction.decision == decision)
    if status is not None:
        query = query.filter(AutonomyAction.status == status)
    if date_from is not None:
        query = query.filter(AutonomyAction.created_at >= date_from)
    if date_to is not None:
        query = query.filter(AutonomyAction.created_at <= date_to)

    total = query.count()
    rows = (
        query.order_by(AutonomyAction.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    return AutonomyActionListResponse(
        items=[AutonomyActionResponse.model_validate(row) for row in rows],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.post("/actions/{action_id}/reverse", response_model=AutonomyActionResponse)
async def reverse(
    action_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AutonomyActionResponse:
    row = _own_action(db, action_id, current_user)
    if row.engine == runner.ENGINE:
        return await _decide(runner.undo, action_id, None, db, current_user)

    # Whatever connector actually executed this action is what must reverse it too — a
    # GraphConnector-executed action reversed through MockConnector would report success
    # without undoing anything real. See app.autonomy.connector_factory.
    connector = get_connector_for_account(db, current_user.account_id)
    try:
        row = reverse_action(db, connector, row)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    db.commit()
    db.refresh(row)
    return AutonomyActionResponse.model_validate(row)


def _own_action(db: Session, action_id: UUID, user: User) -> AutonomyAction:
    row = db.get(AutonomyAction, action_id)
    if row is None or row.account_id != user.account_id:
        raise HTTPException(status_code=404, detail="Action not found.")
    return row


@router.post("/kill-switch", response_model=KillSwitchResponse)
async def kill_switch(
    body: KillSwitchRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> KillSwitchResponse:
    """D5 kill switch: on stops every autonomous action instantly (the engine records
    decisions as halted and performs nothing) and halts pending approvals. Off resumes."""
    row, halted = runner.set_kill_switch(db, current_user.account_id, body.on, current_user, _client_ip(request))
    db.commit()
    return KillSwitchResponse(kill_switch=row.kill_switch, halted_at=row.halted_at, halted_pending_count=halted)


async def _decide(fn, action_id: UUID, request: Request | None, db: Session, user: User) -> AutonomyActionResponse:
    row = _own_action(db, action_id, user)
    try:
        row = fn(db, row, user, _client_ip(request) if request else None)
    except runner.AutonomyError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    db.commit()
    db.refresh(row)
    return AutonomyActionResponse.model_validate(row)


@router.post("/actions/{action_id}/undo", response_model=AutonomyActionResponse)
async def undo_action(
    action_id: UUID,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AutonomyActionResponse:
    """Undo a performed D5 action. Open to any member: undo is the safe direction."""
    return await _decide(runner.undo, action_id, request, db, current_user)


@router.post("/actions/{action_id}/approve", response_model=AutonomyActionResponse)
async def approve_action(
    action_id: UUID,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> AutonomyActionResponse:
    """Approve a recommendation. A Cordon action is performed (and stays undoable); a
    mailbox recommendation is recorded as approved and is never executed by Cordon."""
    return await _decide(runner.approve, action_id, request, db, current_user)


@router.post("/actions/{action_id}/dismiss", response_model=AutonomyActionResponse)
async def dismiss_action(
    action_id: UUID,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AutonomyActionResponse:
    return await _decide(runner.dismiss, action_id, request, db, current_user)


@router.get("/shadow-summary", response_model=ShadowSummaryResponse)
async def shadow_summary(
    days: int = Query(30, ge=1, le=365),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ShadowSummaryResponse:
    """What the engine would have done in shadow mode, per action, and how many of those
    cases an analyst later labelled safe: the false-positive rate to check before going
    active."""
    since = datetime.now(timezone.utc) - timedelta(days=days)
    rows = (
        db.query(AutonomyAction)
        .filter(
            AutonomyAction.account_id == current_user.account_id,
            AutonomyAction.engine == runner.ENGINE,
            AutonomyAction.mode == "shadow",
            AutonomyAction.created_at >= since,
        )
        .all()
    )
    case_ids = {r.case_id for r in rows if r.case_id}
    latest: dict = {}
    if case_ids:
        for label in (
            db.query(Label)
            .filter(Label.account_id == current_user.account_id, Label.case_id.in_(case_ids))
            .order_by(Label.created_at.asc())
            .all()
        ):
            latest[label.case_id] = label.analyst_verdict
    safe_cases = {cid for cid, v in latest.items() if v == "safe"}
    groups: dict[tuple[str, str], ShadowSummaryRow] = {}
    for r in rows:
        key = (r.action_type, r.tier or "")
        g = groups.setdefault(key, ShadowSummaryRow(action_type=r.action_type, tier=r.tier or "", would_have=0,
                                                    within_tier=0, later_labeled_safe=0))
        g.would_have += 1
        g.within_tier += 1 if r.within_tier else 0
        g.later_labeled_safe += 1 if r.case_id in safe_cases else 0
    ordered = sorted(groups.values(), key=lambda g: (g.tier, g.action_type))
    return ShadowSummaryResponse(days=days, cases=len(case_ids), cases_later_labeled_safe=len(safe_cases), rows=ordered)


@router.get("/lists", response_model=list[CordonListEntryResponse])
async def list_entries(
    include_removed: bool = False,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[CordonListEntryResponse]:
    q = db.query(CordonListEntry).filter(CordonListEntry.account_id == current_user.account_id)
    if not include_removed:
        q = q.filter(CordonListEntry.active.is_(True))
    return [CordonListEntryResponse.model_validate(e) for e in q.order_by(CordonListEntry.created_at.desc()).all()]


@router.delete("/lists/{entry_id}", response_model=CordonListEntryResponse)
async def remove_entry(
    entry_id: UUID,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> CordonListEntryResponse:
    """Remove a watch/blocklist entry. When the engine added it, this is the same as
    undoing that action, so the audit row records the reversal too."""
    entry = db.get(CordonListEntry, entry_id)
    if entry is None or entry.account_id != current_user.account_id:
        raise HTTPException(status_code=404, detail="Entry not found.")
    source = db.get(AutonomyAction, entry.source_action_id) if entry.source_action_id else None
    if source is not None and source.engine == runner.ENGINE and source.status == "executed":
        runner.undo(db, source, current_user, _client_ip(request))
    elif entry.active:
        entry.active = False
        entry.removed_at = datetime.now(timezone.utc)
        entry.removed_by = current_user.email
        log_event(db, event_type="cordon_list_entry_removed", account_id=current_user.account_id,
                  user_id=current_user.id, detail={"entry_id": str(entry.id)}, ip_address=_client_ip(request))
    db.commit()
    db.refresh(entry)
    return CordonListEntryResponse.model_validate(entry)


def _to_graph_integration_response(row: GraphIntegration | None) -> GraphIntegrationResponse:
    if row is None:
        return GraphIntegrationResponse(connected=False)
    return GraphIntegrationResponse(
        connected=True,
        tenant_id=row.tenant_id,
        connected_at=row.connected_at,
        is_enabled=row.is_enabled,
    )


@router.get("/graph-integration", response_model=GraphIntegrationResponse)
async def get_graph_integration(
    db: Session = Depends(get_db), current_user: User = Depends(get_current_user)
) -> GraphIntegrationResponse:
    row = (
        db.query(GraphIntegration)
        .filter(GraphIntegration.account_id == current_user.account_id)
        .first()
    )
    return _to_graph_integration_response(row)


@router.put("/graph-integration", response_model=GraphIntegrationResponse)
async def put_graph_integration(
    body: GraphIntegrationRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> GraphIntegrationResponse:
    """Records that this account has completed Microsoft 365 admin consent for Aegis's
    Graph app registration, and which tenant it's for — see DEPLOYMENT.md for the full
    Azure AD setup this depends on. Does not itself verify the tenant_id is real/consented;
    the first real autonomy action against it will surface a clear failure if not (see
    app.autonomy.graph_connector, app.autonomy.executor's execution_failed status)."""
    row = (
        db.query(GraphIntegration)
        .filter(GraphIntegration.account_id == current_user.account_id)
        .first()
    )
    tenant_id = body.tenant_id.strip()
    if row is None:
        row = GraphIntegration(account_id=current_user.account_id, tenant_id=tenant_id)
        db.add(row)
    else:
        row.tenant_id = tenant_id
        row.is_enabled = True

    log_event(
        db,
        event_type="graph_integration_connected",
        account_id=current_user.account_id,
        user_id=current_user.id,
        detail={"tenant_id": tenant_id},
        ip_address=_client_ip(request),
    )

    db.commit()
    db.refresh(row)
    return _to_graph_integration_response(row)
