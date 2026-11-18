"""GET /api/admin/llm-health: does the configured Anthropic key actually work, from inside
the running server? Admin-only.

Answers the question env vars can't: a key can be set and still be revoked, out of credit,
or wrong for the configured model. Makes one minimal call (max_tokens=1) and reports only
whether it worked and the error class. Never echoes the key, any part of it, or the model's
output. Results are cached for 60 seconds so the endpoint can't be used to run up cost.
"""

from __future__ import annotations

import os
import time

import anthropic
from fastapi import APIRouter, Depends

from app.auth.dependencies import require_admin
from app.core.config import settings
from app.db.models import User

router = APIRouter(prefix="/api/admin", tags=["admin"])

_CACHE_SECONDS = 60.0
_cache: dict = {"at": 0.0, "result": None}


def _probe(api_key: str, model: str) -> None:
    """The single network call, isolated for tests."""
    client = anthropic.Anthropic(api_key=api_key)
    client.with_options(timeout=10.0).messages.create(
        model=model, max_tokens=1, messages=[{"role": "user", "content": "ping"}]
    )


@router.get("/llm-health")
def llm_health(_: User = Depends(require_admin)) -> dict:
    now = time.monotonic()
    if _cache["result"] is not None and now - _cache["at"] < _CACHE_SECONDS:
        return {**_cache["result"], "cached": True}

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    result = {
        "enabled": settings.enable_llm_reasoning,
        "key_configured": bool(api_key),
        "model": settings.llm_model,
        "ok": False,
        "error_class": None,
        "latency_ms": None,
    }
    if api_key:
        started = time.monotonic()
        try:
            _probe(api_key, settings.llm_model)
            result["ok"] = True
        except Exception as exc:  # noqa: BLE001 - report the class, never the message
            result["error_class"] = type(exc).__name__
        result["latency_ms"] = int((time.monotonic() - started) * 1000)
    else:
        result["error_class"] = "NoApiKey"
    _cache.update(at=now, result=result)
    return {**result, "cached": False}
