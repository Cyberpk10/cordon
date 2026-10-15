"""Security-headers middleware (M8 Stage 5 security hardening) — adds a fixed set of
browser-enforced defensive headers to every response. These are blunt, well-understood
mitigations for a handful of common web attack classes (clickjacking, MIME-sniffing,
referrer leakage, protocol downgrade) that cost nothing functionally for an API: no page here
is meant to be framed, sniffed as something other than its declared type, or fetched over
plain HTTP.
"""

from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

# Deny every powerful browser feature by default — this API serves JSON and auth pages, no
# camera/microphone/geolocation/payment surface exists anywhere in it.
_PERMISSIONS_POLICY = (
    "camera=(), microphone=(), geolocation=(), payment=(), usb=(), "
    "accelerometer=(), gyroscope=(), magnetometer=()"
)

# 2 years, applies to subdomains, eligible for browser preload lists — the standard
# "we will never knowingly serve this origin over plain HTTP" declaration. Safe to send even
# over a local http:// dev request: browsers only honor HSTS on a response actually received
# over HTTPS, so this is a no-op in local dev rather than something that needs prod-gating.
_HSTS_VALUE = "max-age=63072000; includeSubDomains; preload"

_SENSITIVE_PATH_PREFIXES = ("/api/auth",)


def apply_security_headers(response: Response, path: str) -> Response:
    """The actual header-setting logic, factored out so it can be called from two places
    that need it for different reasons: SecurityHeadersMiddleware below (every ordinary
    response), and app.main's catch-all `@app.exception_handler(Exception)` (a response for
    an unhandled exception never reaches SecurityHeadersMiddleware at all — FastAPI/Starlette
    runs a bare-`Exception` handler inside ServerErrorMiddleware, which sits structurally
    OUTSIDE every app.add_middleware() layer, not inside it like every other exception type.
    Calling this helper directly from that handler is the only way those responses get the
    same headers as everything else)."""
    response.headers["Strict-Transport-Security"] = _HSTS_VALUE
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = _PERMISSIONS_POLICY
    if path.startswith(_SENSITIVE_PATH_PREFIXES):
        # Tokens and credentials must never be cached by a shared proxy or sit in browser
        # disk/back-forward cache after the user navigates away.
        response.headers["Cache-Control"] = "no-store"
    return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Added last in app.main so it's the outermost *middleware* layer — it runs on every
    ordinary response that leaves the app, including ones produced by other middleware (CORS,
    the rate limiter's 429, MaxBodySizeMiddleware's 413), not just ones reaching a route
    handler. The one case it can't cover — a response built by the catch-all Exception
    handler — is handled by that handler calling apply_security_headers() directly; see its
    docstring above."""

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        return apply_security_headers(response, request.url.path)
