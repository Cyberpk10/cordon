"""GET/POST/DELETE /api/vendor-domains — an account's customer-supplied trusted-vendor
domain allowlist (M8 Stage 3a). Reads open to any authenticated user of the account, writes
admin-gated — same pattern as other account-scoped configuration. Consumed by
app.indicators.sender_history via app.sender_history.loader: a domain here is always
classified ESTABLISHED regardless of correspondence history."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.auth.dependencies import get_current_user, require_admin
from app.db.models import TrustedVendorDomain, User
from app.db.session import get_db
from app.indicators.domain_utils import registrable_domain
from app.models.schemas import (
    TrustedVendorDomainCreateRequest,
    TrustedVendorDomainListResponse,
    TrustedVendorDomainResponse,
)

router = APIRouter(prefix="/api/vendor-domains", tags=["vendor-domains"])


@router.get("", response_model=TrustedVendorDomainListResponse)
async def list_vendor_domains(
    db: Session = Depends(get_db), current_user: User = Depends(get_current_user)
) -> TrustedVendorDomainListResponse:
    rows = (
        db.query(TrustedVendorDomain)
        .filter(TrustedVendorDomain.account_id == current_user.account_id)
        .order_by(TrustedVendorDomain.created_at.desc())
        .all()
    )
    return TrustedVendorDomainListResponse(
        items=[TrustedVendorDomainResponse.model_validate(r) for r in rows]
    )


@router.post("", response_model=TrustedVendorDomainResponse, status_code=201)
async def add_vendor_domain(
    payload: TrustedVendorDomainCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> TrustedVendorDomainResponse:
    domain = registrable_domain(payload.domain.strip().lower())
    if not domain or "." not in domain:
        raise HTTPException(status_code=400, detail="Invalid domain.")

    row = TrustedVendorDomain(
        id=uuid.uuid4(),
        account_id=current_user.account_id,
        domain=domain,
        label=payload.label,
        added_by_user_id=current_user.id,
    )
    db.add(row)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=409, detail="This domain is already on the trusted-vendor list."
        ) from None
    db.refresh(row)
    return TrustedVendorDomainResponse.model_validate(row)


@router.delete("/{vendor_domain_id}", status_code=204)
async def remove_vendor_domain(
    vendor_domain_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> None:
    row = (
        db.query(TrustedVendorDomain)
        .filter(
            TrustedVendorDomain.id == vendor_domain_id,
            TrustedVendorDomain.account_id == current_user.account_id,
        )
        .first()
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Not found.")
    db.delete(row)
    db.commit()
