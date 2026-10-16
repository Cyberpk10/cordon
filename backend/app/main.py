"""Aegis backend — FastAPI application entrypoint."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.api.routes.activity_log import router as activity_log_router
from app.api.routes.analyze import router as analyze_router
from app.api.routes.audit import router as audit_router
from app.api.routes.auth import router as auth_router
from app.api.routes.autonomy import router as autonomy_router
from app.api.routes.cases import router as cases_router
from app.api.routes.copilot import router as copilot_router
from app.api.routes.dashboard import router as dashboard_router
from app.api.routes.early_warning import router as early_warning_router
from app.api.routes.events import router as events_router
from app.api.routes.human_risk import router as human_risk_router
from app.api.routes.inbound import router as inbound_router
from app.api.routes.incidents import router as incidents_router
from app.api.routes.investigations import cases_router as investigations_cases_router
from app.api.routes.investigations import incidents_router as investigations_incidents_router
from app.api.routes.labels import router as labels_router
from app.api.routes.messages import router as messages_router
from app.api.routes.monitoring import router as monitoring_router
from app.api.routes.remediation import cases_router as remediation_cases_router
from app.api.routes.remediation import incidents_router as remediation_incidents_router
from app.api.routes.remediation import targets_router as targets_router
from app.api.routes.reports import router as reports_router
from app.api.routes.risk import router as risk_router
from app.api.routes.simulation import router as simulation_router
from app.api.routes.threat_level import router as threat_level_router
from app.api.routes.vendor_domains import router as vendor_domains_router
from app.auth.rate_limit import limiter
from app.core.body_limit import MaxBodySizeMiddleware
from app.core.config import settings
from app.core.security_headers import SecurityHeadersMiddleware, apply_security_headers
from app.db.session import Base, engine, get_db
from app.storage.raw_email_store import purge_expired

logging.basicConfig(
    level=settings.log_level,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # SQLite fallback (local dev without Docker/Alembic): create tables if missing. Real
    # Postgres deployments are expected to have run `alembic upgrade head` instead.
    if settings.database_url.startswith("sqlite"):
        Base.metadata.create_all(bind=engine)
    purge_expired()
    yield


def create_app() -> FastAPI:
    """Factory, not just a module-level singleton, specifically so docs_url/redoc_url/
    openapi_url (computed from settings.environment below) can be exercised by tests under
    both environments — monkeypatch settings.environment, call create_app() again, and the
    new instance reflects it, the same way every other settings-driven behavior in this app
    is tested (see app.api.routes.auth._ensure_dev_autologin_allowed for the request-time
    equivalent of this same settings.environment == "production" gate)."""
    is_production = settings.environment == "production"

    app = FastAPI(
        title="Cordon",
        description="Defensive email-security analysis API.",
        version="0.1.0",
        lifespan=lifespan,
        # API docs are a disclosure surface — the full schema, every route, every request/
        # response field — with no purpose in a production deployment nobody but Cordon's
        # own frontend calls. Disabled outright (not just unlinked) so /docs, /redoc, and
        # /openapi.json all 404 in production rather than existing-but-undiscoverable.
        docs_url=None if is_production else "/docs",
        redoc_url=None if is_production else "/redoc",
        openapi_url=None if is_production else "/openapi.json",
    )

    # Rate limiting (M8 Stage 2, expanded in the Stage 5 hardening pass) — only
    # app.api.routes.auth's login/signup/refresh/password-reset/invite-accept endpoints
    # actually apply @limiter.limit(...); everything else is unaffected. In-memory storage,
    # see app.auth.rate_limit for why that's the right choice for the current single-instance
    # deployment.
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    app.add_middleware(SlowAPIMiddleware)

    # Gated to production only — HTTPSRedirectMiddleware would otherwise break local
    # http://localhost dev. Relies on the ASGI server trusting X-Forwarded-Proto from the
    # platform's TLS-terminating proxy (uvicorn's --proxy-headers, see docker-entrypoint.sh) —
    # without that, Starlette can't see the real scheme and this would redirect-loop.
    if is_production:
        app.add_middleware(HTTPSRedirectMiddleware)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Security review (M8 Stage 4) — rejects an oversized request from its declared
    # Content-Length before any route reads the body. See app.core.body_limit.
    app.add_middleware(MaxBodySizeMiddleware, max_bytes=settings.max_request_body_bytes)

    # Added last so it's the outermost middleware layer (Starlette wraps in reverse add
    # order) — every response leaving the app gets these headers, including ones produced
    # by the middleware above it (a CORS preflight, a 429 from the rate limiter, a 413 from
    # MaxBodySizeMiddleware), not just ones that reach a route handler. See
    # app.core.security_headers for what it sets and why.
    app.add_middleware(SecurityHeadersMiddleware)

    app.include_router(auth_router)
    app.include_router(analyze_router)
    app.include_router(activity_log_router)
    app.include_router(cases_router)
    app.include_router(labels_router)
    app.include_router(dashboard_router)
    app.include_router(audit_router)
    app.include_router(remediation_cases_router)
    app.include_router(targets_router)
    app.include_router(copilot_router)
    app.include_router(risk_router)
    app.include_router(reports_router)
    app.include_router(events_router)
    app.include_router(incidents_router)
    app.include_router(remediation_incidents_router)
    app.include_router(autonomy_router)
    app.include_router(monitoring_router)
    app.include_router(messages_router)
    app.include_router(inbound_router)
    app.include_router(simulation_router)
    app.include_router(human_risk_router)
    app.include_router(vendor_domains_router)
    app.include_router(threat_level_router)
    app.include_router(early_warning_router)
    app.include_router(investigations_cases_router)
    app.include_router(investigations_incidents_router)

    @app.get("/health")
    async def health(db: Session = Depends(get_db)) -> dict[str, str]:
        """Liveness + readiness: also confirms the database is actually reachable, so a
        deploy doesn't report healthy while the DB is down."""
        try:
            db.execute(text("SELECT 1"))
        except Exception as exc:  # noqa: BLE001 - surface any DB failure as a 503, not a 500
            # /health is unauthenticated by design (it's what the deployment platform polls),
            # so the raw exception — which can include the DB host, port, or driver-level
            # detail — stays server-side only; the public response says just enough to be a
            # useful liveness signal.
            logger.error("Health check database connectivity failure: %s", exc)
            raise HTTPException(status_code=503, detail="Database unavailable.") from exc
        return {"status": "ok"}

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        """Catch-all for anything that isn't an HTTPException/RequestValidationError (both
        of which FastAPI already handles with their own more-specific handlers registered
        ahead of this one, so this never intercepts an intentional 4xx). The client gets a
        flat, generic message; the real exception — class, message, full traceback — only
        ever reaches the server's own logs via logger.exception, never the response body.
        Without this, Starlette's default (debug=False, which this app never overrides)
        already avoids leaking a traceback, but returns a bare "Internal Server Error" text
        response with no server-side record of what happened — this makes both the client
        contract (JSON, like every other response this API returns) and the operational
        side (an actual log line to investigate) explicit instead of accidental.

        Applies the security headers directly (apply_security_headers) rather than relying
        on SecurityHeadersMiddleware — a handler for the bare `Exception` class runs inside
        Starlette's ServerErrorMiddleware, which sits OUTSIDE every app.add_middleware()
        layer, so this response never passes through SecurityHeadersMiddleware at all. See
        that function's docstring in app.core.security_headers.
        """
        logger.exception(
            "Unhandled exception processing %s %s", request.method, request.url.path
        )
        response = JSONResponse(status_code=500, content={"detail": "Internal server error."})
        return apply_security_headers(response, request.url.path)

    return app


app = create_app()
