"""POST /api/copilot/query — natural-language threat copilot over Aegis's own data.

Defensive/reporting only. Routing picks one of app.copilot.templates.TEMPLATE_REGISTRY's
whitelisted, parameterized templates in two tiers: the deterministic matcher
(app.copilot.intent.match_question) first, so the common/suggested questions work with
no LLM at all; then, only for questions it doesn't recognize and only when an API key is
configured, the LLM router (app.copilot.llm.select_template, a forced tool-use call).
Either way the (template, params) pair is re-validated against the whitelist before
anything executes (app.copilot.templates.execute_template) — the LLM never generates or
influences an actual database query. Narration is the LLM's tool-free second call when
available, else app.copilot.intent.describe_result's template-filled answer from the same
figures — see app/copilot/llm.py for the full security rationale. Requires auth;
every template executes scoped to the authenticated user's own account_id (M8 Stage 2) —
see app.copilot.templates.execute_template's account_id parameter.
"""

from __future__ import annotations

import os
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import ValidationError
from sqlalchemy.orm import Session

from app.auth.dependencies import get_current_user
from app.copilot.intent import describe_result, match_question
from app.copilot.llm import narrate, select_template
from app.copilot.templates import execute_template
from app.core.config import settings
from app.db.models import User
from app.db.session import get_db
from app.models.schemas import CopilotQueryRequest, CopilotQueryResponse, CopilotTemplateUsed

router = APIRouter(prefix="/api/copilot", tags=["copilot"])

_UNRECOGNIZED_QUESTION_DETAIL = (
    "I couldn't match that to a question the copilot can answer from your data. Try asking "
    "about verdict counts (\"how many malicious emails this month\"), top indicators, a "
    "recipient (\"how often was alice@example.com targeted\"), or framework coverage "
    "(\"what's our MITRE coverage\")."
)


@router.post("/query", response_model=CopilotQueryResponse)
async def copilot_query(
    body: CopilotQueryRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> CopilotQueryResponse:
    if not settings.enable_copilot:
        raise HTTPException(
            status_code=503, detail="The copilot is not enabled on this deployment."
        )

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    now = datetime.utcnow()

    selection = match_question(body.question, now)
    if selection is None and api_key:
        selection = select_template(
            body.question, model=settings.llm_model, api_key=api_key, now=now
        )
    if selection is None:
        # No API key -> the LLM router was never available (422: rephrase); a key but no
        # selection -> the LLM call itself failed (502). Same guidance either way.
        raise HTTPException(
            status_code=502 if api_key else 422, detail=_UNRECOGNIZED_QUESTION_DETAIL
        )
    template_name, raw_params = selection

    # Never trust the LLM's output directly: template_name must be a literal whitelist
    # key and raw_params must pass that template's own extra="forbid" schema. This is
    # the real security boundary — it holds even if select_template's output were fully
    # attacker-controlled.
    try:
        resolved_name, params, result = execute_template(
            template_name, raw_params, db, current_user.account_id
        )
    except KeyError as exc:
        raise HTTPException(
            status_code=400, detail=f"Unknown query template: {template_name!r}."
        ) from exc
    except ValidationError as exc:
        raise HTTPException(
            status_code=400, detail=f"Invalid parameters for template {template_name!r}: {exc}"
        ) from exc

    narrative = None
    if api_key:
        narrative = narrate(
            body.question, resolved_name, result, model=settings.llm_model, api_key=api_key
        )
    if narrative is None:
        narrative = describe_result(resolved_name, result)

    return CopilotQueryResponse(
        question=body.question,
        narrative=narrative,
        template_used=CopilotTemplateUsed(
            template=resolved_name, params=params.model_dump(mode="json")
        ),
        result=result,
        generated_at=datetime.utcnow(),
    )
