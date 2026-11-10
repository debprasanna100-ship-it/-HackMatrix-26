"""TrustLens FastAPI application factory."""
from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from .api import auth, routes_analyze, routes_chain, routes_health, routes_message
from .api.ratelimit import RateLimitMiddleware
from .config import Settings, get_settings
from .pipeline.fetcher import SafeFetcher
from .pipeline.ssrf import SystemDnsResolver
from .storage import repository
from .storage.seed import seed_initial_admin
from .storage.database import init_engine
from .web3.registry import build_registry_client, chain_enabled

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("trustlens")


def _error(code: str, message: str, status: int, details=None) -> JSONResponse:
    body = {"error": {"code": code, "message": message}}
    if details is not None:
        body["error"]["details"] = details
    return JSONResponse(status_code=status, content=body)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        init_engine(settings)  # creates tables (SQLite) / runs Alembic (PostgreSQL)
        # Hardened bootstrap: create the configured initial admin (idempotent,
        # from env/CLI — never the first arbitrary registration).
        try:
            await asyncio.to_thread(seed_initial_admin, settings)
        except Exception:
            logger.exception("initial-admin seeding failed at startup")
        # Retention policy (privacy): purge reports older than the configured
        # window at startup. 0 = keep indefinitely.
        if settings.report_retention_days > 0:
            try:
                removed = await asyncio.to_thread(
                    repository.purge_reports_older_than, settings.report_retention_days
                )
                logger.info("retention: removed %d report(s) older than %d day(s)",
                            removed, settings.report_retention_days)
            except Exception:
                logger.exception("retention purge failed at startup")
        logger.info("TrustLens %s starting (%s) — no secrets are logged", settings.version, settings.environment)
        yield
        logger.info("TrustLens shutting down")

    app = FastAPI(
        title="TrustLens API",
        version=settings.version,
        description=(
            "AI-powered web threat detection and digital trust intelligence. "
            "Phase 1: URL normalisation, SSRF-safe fetching with redirect tracing, "
            "and deterministic domain heuristics."
        ),
        lifespan=lifespan,
    )

    app.state.settings = settings
    app.state.resolver = SystemDnsResolver()
    app.state.fetcher = SafeFetcher(settings, app.state.resolver)
    app.state.registry_client = build_registry_client(settings)  # None when chain disabled

    app.add_middleware(
        RateLimitMiddleware,
        limit_per_minute=settings.rate_limit_per_minute,
        trust_proxy=settings.trust_proxy_headers,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        # PATCH is included because PATCH /api/v1/reports/{id} (report
        # visibility toggle) is a browser-accessible route (audit L2).
        allow_methods=["GET", "POST", "PATCH", "DELETE"],
        allow_headers=["*"],
    )

    app.include_router(routes_health.router)
    app.include_router(auth.router)
    app.include_router(routes_analyze.router)
    app.include_router(routes_message.router)
    app.include_router(routes_chain.router)

    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(_: Request, exc: StarletteHTTPException):
        detail = exc.detail
        if isinstance(detail, dict):
            return _error(detail.get("code", "http_error"), detail.get("message", str(detail)), exc.status_code)
        return _error("http_error", str(detail), exc.status_code)

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(_: Request, exc: RequestValidationError):
        return _error("validation_error", "Request payload failed validation.", 422, details=exc.errors())

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(_: Request, exc: Exception):
        logger.exception("unhandled error: %s", type(exc).__name__)
        return _error("internal_error", "An internal error occurred. It has been logged.", 500)

    return app


app = create_app()
