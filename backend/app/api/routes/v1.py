"""Public /v1 API for programmatic callers (the Gmail add-on in integrations/gmail-addon/,
scripts).

- POST /v1/keys, GET /v1/keys, DELETE /v1/keys/{id}: a logged-in user (JWT, same as the web
  app) mints, lists and revokes their API keys. The raw key is returned once, at creation.
- POST /v1/analyze/email: API key only (Authorization: Bearer cdn_...). Runs the exact
  pipeline and persistence path as the web app's paste/upload analyze
  (app.api.routes.analyze.persist_case_and_build_response over run_email_pipeline), so the
  result is a normal Case in the account, then flattens it to the stable contract in
  app.analysis.public_contract.
- POST /v1/assistant: API key only. Answers one question about one email (the Outlook
  add-in's chat), grounded only in Cordon's analysis of it; see app.assistant. Reuses the
  saved Case, or the short-lived app.analysis.result_cache entry, for the same content.

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

from app.analysis import result_cache
from app.analysis.email_pipeline import PipelineResult, run_email_pipeline
from app.analysis.public_contract import build_public_result, public_verdict
from app.api.routes.analyze import persist_case_and_build_response
from app.assistant.answer import answer_question
from app.assistant.facts import build_facts
from app.auth.api_keys import api_key_rate_limit_key, generate_api_key, get_api_key
from app.auth.audit_log import log_event
from app.auth.dependencies import get_current_user
from app.auth.rate_limit import API_KEY_ANALYZE_RATE_LIMIT, API_KEY_ASSISTANT_RATE_LIMIT, limiter
from app.core.config import settings
from app.db.models import ApiKey, Case, Investigation, User
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
    V1AssistantRequest,
    V1AssistantResponse,
    V1GroundedOn,
    V1Investigation,
    Verdict,
)
from app.parsing.eml_parser import parse_eml
from app.sender_baseline.loader import baseline_lookup_for, record_observation
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


def _case_mappings(case: Case) -> dict[str, list[FrameworkControlRef]]:
    return {
        key: [FrameworkControlRef.model_validate(r) for r in refs]
        for key, refs in (case.framework_mappings or {}).items()
    }


def _case_indicators(case: Case) -> list[Indicator]:
    return [Indicator.model_validate(i) for i in (case.indicators or [])]


def _takeover_fields(account_takeover: dict | None, sender_baseline: dict | None) -> dict:
    """The additive account-takeover keys: the finding as-is, and the baseline reduced to
    its status and one-line summary."""
    return {
        "account_takeover": account_takeover,
        "sender_baseline": (
            {"status": sender_baseline["status"], "summary": sender_baseline["summary"]}
            if sender_baseline
            else None
        ),
    }


def _investigation_field(db: Session, account_id, case_id) -> dict:
    """The additive `investigation` key, from the case's stored investigation report."""
    inv = (
        db.query(Investigation)
        .filter(Investigation.account_id == account_id, Investigation.case_id == case_id)
        .first()
    )
    report = inv.report if inv is not None else None
    if not report:
        return {"investigation": None}
    conf = report["confidence"]
    return {
        "investigation": {
            "engine": report["engine"],
            "narrative": report["narrative"],
            "confidence": conf["level"],
            "confidence_note": conf["reasons"][-1] if conf["level"] == "low" and conf["reasons"] else None,
            "hypothesis": report["hypothesis"]["label"],
            "campaign": report["campaign"]["status"],
            "recommended_action": report["recommendation"]["title"],
            "suggested_tier": report["recommendation"]["suggested_tier"],
        }
    }


def _stored_report(db: Session, case: Case) -> dict | None:
    inv = (
        db.query(Investigation)
        .filter(Investigation.account_id == case.account_id, Investigation.case_id == case.id)
        .first()
    )
    return inv.report if inv is not None else None


def _from_existing_case(case: Case, raw_bytes: bytes, db: Session | None = None) -> V1AnalyzeEmailResponse:
    return V1AnalyzeEmailResponse.model_validate(
        build_public_result(
            verdict=Verdict(case.verdict),
            score=case.score,
            indicators=_case_indicators(case),
            framework_mappings=_case_mappings(case),
            auth_results=_auth_results(raw_bytes),
            llm_intent_category=case.llm_intent_category,
        )
        | _takeover_fields(case.account_takeover, case.sender_baseline)
        | (_investigation_field(db, case.account_id, case.id) if db is not None else {})
    )


def _from_pipeline_result(result: PipelineResult) -> V1AnalyzeEmailResponse:
    return V1AnalyzeEmailResponse.model_validate(
        build_public_result(
            verdict=result.verdict,
            score=result.score,
            indicators=result.indicators,
            framework_mappings=result.framework_mappings,
            auth_results=result.parsed.auth_results,
            llm_intent_category=result.llm_intent_category,
        )
        | _takeover_fields(result.account_takeover, result.sender_baseline)
    )


def _validated_raw_bytes(raw_email: str) -> bytes:
    if not raw_email.strip():
        raise HTTPException(status_code=422, detail="raw_email is empty.")
    raw_bytes = raw_email.encode("utf-8")
    if len(raw_bytes) > settings.max_upload_bytes:
        raise HTTPException(status_code=413, detail="Email exceeds the maximum allowed size.")
    return raw_bytes


def _lookup_or_run(
    db: Session, api_key: ApiKey, raw_bytes: bytes, content_hash: str
) -> tuple[Case | None, PipelineResult | None]:
    """The one analysis path shared by /analyze/email and /assistant. Returns the saved Case
    for this exact content if the account has one, otherwise a pipeline result (from the
    short-lived cache, or a fresh run). Never persists anything itself."""
    existing = (
        db.query(Case)
        .filter(Case.account_id == api_key.account_id, Case.content_hash == content_hash)
        .order_by(Case.created_at.desc())
        .first()
    )
    if existing is not None:
        return existing, None
    cached = result_cache.get(api_key.account_id, content_hash)
    if cached is not None:
        return None, cached
    history = load_sender_history(db, api_key.account_id)
    try:
        result = run_email_pipeline(raw_bytes, history, baseline_lookup_for(db, api_key.account_id))
    except Exception as exc:  # noqa: BLE001 - same contract as the web paste route
        raise HTTPException(status_code=400, detail="Could not parse the email content.") from exc
    result_cache.put(api_key.account_id, content_hash, result, len(raw_bytes))
    return None, result


@router.post("/analyze/email", response_model=V1AnalyzeEmailResponse)
@limiter.limit(API_KEY_ANALYZE_RATE_LIMIT, key_func=api_key_rate_limit_key)
def analyze_email_v1(
    request: Request,
    payload: V1AnalyzeEmailRequest,
    db: Session = Depends(get_db),
    api_key: ApiKey = Depends(get_api_key),
) -> V1AnalyzeEmailResponse:
    raw_bytes = _validated_raw_bytes(payload.raw_email)
    content_hash = hashlib.sha256(raw_bytes).hexdigest()
    existing, result = _lookup_or_run(db, api_key, raw_bytes, content_hash)
    if existing is not None:
        db.commit()  # persist last_used_at
        return _from_existing_case(existing, raw_bytes, db)
    assert result is not None

    if payload.persist == "if_not_clean" and public_verdict(result.verdict) == "clean":
        # Clean and the caller asked not to keep clean mail: return the identical contract
        # straight from the pipeline result. No Case, no raw-email file, no sender-history or
        # threat-level side effects. The one thing kept is a metadata-only sender observation
        # (app.sender_baseline): a sender's baseline has to be built from their normal mail.
        record_observation(
            db, api_key.account_id, content_hash, result.sender_signals, result.verdict.value
        )
        db.commit()  # persist last_used_at and the observation
        return _from_pipeline_result(result)

    user = db.get(User, api_key.user_id)  # get_api_key already verified it exists and is active
    subject = result.parsed.subject or "api-email"
    saved = persist_case_and_build_response(
        raw_bytes, subject[:200] + ".eml", result, user, db, content_hash=content_hash
    )
    response = _from_pipeline_result(result)
    investigation = _investigation_field(db, api_key.account_id, saved.id)["investigation"]
    if investigation is not None:
        response = response.model_copy(update={"investigation": V1Investigation.model_validate(investigation)})
    return response


# ---- assistant (API key) ------------------------------------------------------------------


@router.post("/assistant", response_model=V1AssistantResponse)
@limiter.limit(API_KEY_ASSISTANT_RATE_LIMIT, key_func=api_key_rate_limit_key)
def assistant_v1(
    request: Request,
    payload: V1AssistantRequest,
    db: Session = Depends(get_db),
    api_key: ApiKey = Depends(get_api_key),
) -> V1AssistantResponse:
    """Answers one question about one email, grounded only in Cordon's analysis of it (see
    app.assistant). Reuses the saved Case or cached analysis when there is one; never
    creates a Case."""
    if not payload.question.strip():
        raise HTTPException(status_code=422, detail="question is empty.")
    raw_bytes = _validated_raw_bytes(payload.raw_email)
    content_hash = hashlib.sha256(raw_bytes).hexdigest()
    existing, result = _lookup_or_run(db, api_key, raw_bytes, content_hash)
    db.commit()  # persist last_used_at

    if existing is not None:
        try:
            parsed = parse_eml(raw_bytes)
        except Exception as exc:  # noqa: BLE001 - it parsed when the Case was created
            raise HTTPException(status_code=400, detail="Could not parse the email content.") from exc
        facts = build_facts(
            verdict=Verdict(existing.verdict),
            score=existing.score,
            indicators=_case_indicators(existing),
            framework_mappings=_case_mappings(existing),
            parsed=parsed,
            sender_baseline=existing.sender_baseline,
            investigation_report=_stored_report(db, existing),
        )
    else:
        assert result is not None
        facts = build_facts(
            verdict=result.verdict,
            score=result.score,
            indicators=result.indicators,
            framework_mappings=result.framework_mappings,
            parsed=result.parsed,
            sender_baseline=result.sender_baseline,
        )

    history = [t.model_dump() for t in payload.history]
    reply = answer_question(facts, payload.question, history)
    return V1AssistantResponse(
        answer=reply.answer,
        grounded_on=V1GroundedOn(verdict=facts.verdict, score=facts.score),
        refused=reply.refused,
    )
