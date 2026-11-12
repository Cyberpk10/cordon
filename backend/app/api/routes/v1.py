"""Public /v1 API for programmatic callers (the Gmail add-on in integrations/gmail-addon/,
scripts).

- POST /v1/keys, GET /v1/keys, DELETE /v1/keys/{id}: a logged-in user (JWT, same as the web
  app) mints, lists and revokes their API keys. The raw key is returned once, at creation.
- POST /v1/analyze/email: API key only (Authorization: Bearer cdn_...). Runs the exact
  pipeline and persistence path as the web app's paste/upload analyze
  (app.api.routes.analyze.persist_case_and_build_response over run_email_pipeline), so the
  result is a normal Case in the account, then flattens it to the stable contract in
  app.analysis.public_contract.

`persist` (request body): "always" (default) saves every result as a Case; "if_not_clean"
saves only suspicious/malicious results and returns clean ones without saving anything. The
Gmail add-on auto-analyzes every opened message with "if_not_clean".

Re-analyzing byte-identical content in the same account returns the existing Case's result
instead of creating a duplicate. Without this, each re-analysis of a saved email would add a
Case, and the sender's own earlier Case would turn "first contact" into "seen before",
changing the score of the same email between analyses.

Server-to-server calls (Google's Apps Script servers) send no Origin header, so CORS never
applies to them, and the app has no TrustedHostMiddleware. Nothing here needs CORS changes.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.analysis.email_pipeline import run_email_pipeline
from app.analysis.public_contract import build_public_result, public_verdict
from app.api.routes.analyze import persist_case_and_build_response
from app.auth.api_keys import api_key_rate_limit_key, generate_api_key, get_api_key
from app.auth.audit_log import log_event
from app.auth.dependencies import get_current_user
from app.auth.rate_limit import API_KEY_ANALYZE_RATE_LIMIT, limiter
from app.core.config import settings
from app.db.models import ApiKey, Case, User
from app.db.session import get_db
from app.models.schemas import (
    ApiKeyCreatedResponse,
    ApiKeyCreateRequest,
    ApiKeyListResponse,
    ApiKeySummary,
    AuthResults,
    FrameworkControlRef,
    Indicator,
    V1AnalyzeEmailRequest,
    V1AnalyzeEmailResponse,
    Verdict,
)
from app.parsing.eml_parser import parse_eml
from app.sender_history.loader import load_sender_history

router = APIRouter(prefix="/v1", tags=["v1"])


def _summary(key: ApiKey) -> ApiKeySummary:
    return ApiKeySummary(
        id=key.id,
        name=key.name,
        prefix=key.prefix,
        created_at=key.created_at,
        last_used_at=key.last_used_at,
        revoked_at=key.revoked_at,
    )


# ---- key management (logged-in user, JWT) -------------------------------------------------


@router.post("/keys", response_model=ApiKeyCreatedResponse, status_code=201)
def create_api_key(
    payload: ApiKeyCreateRequest | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ApiKeyCreatedResponse:
    name = (payload.name if payload else "API key").strip() or "API key"
    raw, prefix, key_hash = generate_api_key()
    key = ApiKey(
        id=uuid.uuid4(),
        account_id=current_user.account_id,
        user_id=current_user.id,
        name=name,
        prefix=prefix,
        key_hash=key_hash,
    )
    db.add(key)
    log_event(
        db,
        event_type="api_key_created",
        account_id=current_user.account_id,
        user_id=current_user.id,
        detail={"api_key_id": str(key.id), "prefix": prefix},
    )
    db.commit()
    db.refresh(key)
    return ApiKeyCreatedResponse(**_summary(key).model_dump(), key=raw)


def _visible_keys_query(db: Session, user: User):
    q = db.query(ApiKey).filter(ApiKey.account_id == user.account_id)
    if user.role != "admin":
        q = q.filter(ApiKey.user_id == user.id)
    return q


@router.get("/keys", response_model=ApiKeyListResponse)
def list_api_keys(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ApiKeyListResponse:
    keys = _visible_keys_query(db, current_user).order_by(ApiKey.created_at.desc()).all()
    return ApiKeyListResponse(keys=[_summary(k) for k in keys])


@router.delete("/keys/{key_id}", status_code=204)
def revoke_api_key(
    key_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> None:
    key = _visible_keys_query(db, current_user).filter(ApiKey.id == key_id).first()
    if key is None:
        raise HTTPException(status_code=404, detail="API key not found.")
    if key.revoked_at is None:
        key.revoked_at = datetime.now(timezone.utc)
        log_event(
            db,
            event_type="api_key_revoked",
            account_id=current_user.account_id,
            user_id=current_user.id,
            detail={"api_key_id": str(key.id), "prefix": key.prefix},
        )
        db.commit()


# ---- analysis (API key) -------------------------------------------------------------------


def _auth_results(raw_bytes: bytes) -> AuthResults:
    try:
        return parse_eml(raw_bytes).auth_results
    except Exception:  # noqa: BLE001 - it parsed when the Case was created; be safe anyway
        return AuthResults()


def _from_existing_case(case: Case, raw_bytes: bytes) -> V1AnalyzeEmailResponse:
    mappings = {
        key: [FrameworkControlRef.model_validate(r) for r in refs]
        for key, refs in (case.framework_mappings or {}).items()
    }
    return V1AnalyzeEmailResponse.model_validate(
        build_public_result(
            verdict=Verdict(case.verdict),
            score=case.score,
            indicators=[Indicator.model_validate(i) for i in (case.indicators or [])],
            framework_mappings=mappings,
            auth_results=_auth_results(raw_bytes),
            llm_intent_category=case.llm_intent_category,
        )
    )


@router.post("/analyze/email", response_model=V1AnalyzeEmailResponse)
@limiter.limit(API_KEY_ANALYZE_RATE_LIMIT, key_func=api_key_rate_limit_key)
def analyze_email_v1(
    request: Request,
    payload: V1AnalyzeEmailRequest,
    db: Session = Depends(get_db),
    api_key: ApiKey = Depends(get_api_key),
) -> V1AnalyzeEmailResponse:
    if not payload.raw_email.strip():
        raise HTTPException(status_code=422, detail="raw_email is empty.")
    raw_bytes = payload.raw_email.encode("utf-8")
    if len(raw_bytes) > settings.max_upload_bytes:
        raise HTTPException(status_code=413, detail="Email exceeds the maximum allowed size.")

    user = db.get(User, api_key.user_id)  # get_api_key already verified it exists and is active
    content_hash = hashlib.sha256(raw_bytes).hexdigest()

    existing = (
        db.query(Case)
        .filter(Case.account_id == api_key.account_id, Case.content_hash == content_hash)
        .order_by(Case.created_at.desc())
        .first()
    )
    if existing is not None:
        db.commit()  # persist last_used_at
        return _from_existing_case(existing, raw_bytes)

    history = load_sender_history(db, api_key.account_id)
    try:
        result = run_email_pipeline(raw_bytes, history)
    except Exception as exc:  # noqa: BLE001 - same contract as the web paste route
        raise HTTPException(status_code=400, detail="Could not parse the email content.") from exc

    if payload.persist == "if_not_clean" and public_verdict(result.verdict) == "clean":
        # Clean and the caller asked not to keep clean mail: return the identical contract
        # straight from the pipeline result. No Case, no raw-email file, no sender-history or
        # threat-level side effects.
        db.commit()  # persist last_used_at
        return V1AnalyzeEmailResponse.model_validate(
            build_public_result(
                verdict=result.verdict,
                score=result.score,
                indicators=result.indicators,
                framework_mappings=result.framework_mappings,
                auth_results=result.parsed.auth_results,
                llm_intent_category=result.llm_intent_category,
            )
        )

    subject = result.parsed.subject or "api-email"
    analyzed = persist_case_and_build_response(
        raw_bytes, subject[:200] + ".eml", result, user, db, content_hash=content_hash
    )
    return V1AnalyzeEmailResponse.model_validate(
        build_public_result(
            verdict=analyzed.verdict,
            score=analyzed.score,
            indicators=analyzed.indicators,
            framework_mappings=analyzed.framework_mappings,
            auth_results=result.parsed.auth_results,
            llm_intent_category=analyzed.llm_intent_category,
        )
    )
