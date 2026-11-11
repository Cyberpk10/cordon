"""API-key authentication for programmatic callers of the /v1 endpoints (the Gmail add-on,
scripts). Separate from the JWT path in app.auth.dependencies on purpose: a JWT is a short-
lived browser session, an API key is a long-lived credential pasted into another system,
and the two must never be accepted interchangeably. /v1/analyze/email takes ONLY an API key;
the JWT routes never accept one.

Keys look like `cdn_<43 url-safe chars>` (256 bits of entropy). Only the SHA-256 hash is
stored (app.auth.security.hash_token, the same scheme refresh tokens use). Every request
re-checks the key row and its owning user, so revoking a key or deactivating its user takes
effect immediately.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timezone

from fastapi import Depends, Header, HTTPException, Request
from sqlalchemy.orm import Session

from app.auth.security import hash_token
from app.db.models import ApiKey, User
from app.db.session import get_db

KEY_PREFIX = "cdn_"
_DISPLAY_PREFIX_LEN = len(KEY_PREFIX) + 6

_UNAUTHORIZED = HTTPException(
    status_code=401,
    detail="Invalid or missing API key.",
    headers={"WWW-Authenticate": "Bearer"},
)


def generate_api_key() -> tuple[str, str, str]:
    """Returns (raw_key, display_prefix, key_hash). The raw key is shown to the user once."""
    raw = KEY_PREFIX + secrets.token_urlsafe(32)
    return raw, raw[:_DISPLAY_PREFIX_LEN], hash_token(raw)


def _bearer(authorization: str | None) -> str | None:
    if not authorization or not authorization.lower().startswith("bearer "):
        return None
    token = authorization.split(" ", 1)[1].strip()
    return token or None


def get_api_key(
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> ApiKey:
    token = _bearer(authorization)
    # Cheap shape check first: a JWT or random string never touches the DB.
    if token is None or not token.startswith(KEY_PREFIX):
        raise _UNAUTHORIZED
    key = db.query(ApiKey).filter(ApiKey.key_hash == hash_token(token)).first()
    if key is None or key.revoked_at is not None:
        raise _UNAUTHORIZED
    user = db.get(User, key.user_id)
    if user is None or not user.is_active or user.account_id != key.account_id:
        raise _UNAUTHORIZED
    key.last_used_at = datetime.now(timezone.utc)
    return key


def api_key_rate_limit_key(request: Request) -> str:
    """slowapi key function: buckets requests per presented key (by hash, so the raw key
    never sits in limiter storage). Only reached after get_api_key has accepted the key,
    since FastAPI resolves dependencies before slowapi's decorator runs the limit check."""
    token = _bearer(request.headers.get("authorization")) or ""
    return "apikey:" + hashlib.sha256(token.encode("utf-8")).hexdigest()[:32]
