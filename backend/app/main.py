"""FastAPI application factory and API gateway entry point.

Routers are mounted here one per domain.  Phase 1 exposes health and metadata
only; auth, sessions, devices, policies, trust, alerts and audit are mounted as
their phases land.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from contextlib import asynccontextmanager

from app.core.databroker import databroker_mesh
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.api import (
    ai_narrator, alerts, audit, auth, blocked_ips, dashboard, devices, edr,
    health, oauth, pdp, policies, proxy, resources, sessions, signals,
    simulator, trust, users, vault, voice_alerts, ws,
)
from app.plugins import gateway_auth
from app.scim import router as scim_router
from app.core.config import settings
from app.middleware.context import ContextCollectorMiddleware
from app.middleware.device_binding import DeviceBindingMiddleware
from app.middleware.ip_blocker import IPBlockerMiddleware
from app.middleware.waf import WAFMiddleware
from app.services.events import bus
from app.workers import continuous_verification
from app.middleware.gateway import RateLimitMiddleware
from app.schemas.common import ErrorResponse

logging.basicConfig(
    level=logging.DEBUG if settings.debug else logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s :: %(message)s",
)
logger = logging.getLogger("ztna")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(
        "Starting %s (env=%s, db=%s)",
        settings.app_name,
        settings.app_env,
        settings.database_url.split("://", 1)[0],
    )

    stop = asyncio.Event()
    tasks: list[asyncio.Task] = []

    # A Redis-backed bus needs its relay running before anyone subscribes.
    starter = getattr(bus, "start", None)
    if starter is not None:
        await starter()
        
    databroker_mesh.start()

    if settings.verification_in_api:
        # No Redis: the in-process event bus cannot cross a process boundary,
        # so the sweep runs here, where the WebSocket subscribers actually are.
        # A sweep publishing into a bus nobody could subscribe to would look
        # like it was working and do nothing.
        logger.info(
            "Continuous verification will run inside the API process "
            "(no REDIS_URL configured)."
        )
        tasks.append(
            asyncio.create_task(
                continuous_verification.verification_loop(stop),
                name="continuous-verification",
            )
        )
    else:
        logger.info(
            "Continuous verification is owned by the worker process; this API "
            "relays its events over Redis."
        )

    try:
        yield
    finally:
        stop.set()
        for task in tasks:
            task.cancel()
        for task in tasks:
            with contextlib.suppress(asyncio.CancelledError):
                await task
        stopper = getattr(bus, "stop", None)
        if stopper is not None:
            await stopper()
        logger.info("Shutting down %s", settings.app_name)


def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.app_name,
        description=(
            "Zero Trust Network Access gateway with adaptive trust scoring and "
            "continuous risk monitoring."
        ),
        version=health.VERSION,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )

    # Middleware stack, outermost first at runtime:
    #   CORS -> IP Blocker -> WAF -> Device Binding -> Context Collector -> Rate Limit -> Routes
    # Starlette executes middleware in reverse order of addition.
    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(ContextCollectorMiddleware)
    app.add_middleware(DeviceBindingMiddleware)
    app.add_middleware(WAFMiddleware)
    app.add_middleware(IPBlockerMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=[
            "X-Request-ID",
            "X-Access-Gate",
            "X-Trust-Score",
            "X-WAF-Blocked",
            "X-WAF-Risk-Score",
            "X-IP-Blocked",
        ],
    )

    # --- Error handling: clients get a message, logs get the traceback ------
    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, exc: StarletteHTTPException):
        # Headers set on the exception carry meaning the client needs:
        # WWW-Authenticate says *why* a 401 happened (so the browser knows
        # whether refreshing would help), Retry-After paces a 429, and
        # X-Access-Gate names which policy gate refused a 403. Dropping them
        # turns an actionable refusal into an opaque one.
        return JSONResponse(
            status_code=exc.status_code,
            content=ErrorResponse(
                detail=str(exc.detail),
                code=f"http_{exc.status_code}",
                request_id=getattr(request.state, "request_id", None),
            ).model_dump(),
            headers=getattr(exc, "headers", None),
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        request: Request, exc: RequestValidationError
    ):
        logger.warning("Validation error on %s: %s", request.url.path, exc.errors())
        return JSONResponse(
            status_code=422,
            content=ErrorResponse(
                detail="Request validation failed.",
                code="validation_error",
                request_id=getattr(request.state, "request_id", None),
            ).model_dump(),
        )

    @app.exception_handler(SQLAlchemyError)
    async def database_exception_handler(request: Request, exc: SQLAlchemyError):
        logger.exception("Database error on %s", request.url.path)
        return JSONResponse(
            status_code=503,
            content=ErrorResponse(
                detail="A database error occurred. Please retry shortly.",
                code="database_error",
                request_id=getattr(request.state, "request_id", None),
            ).model_dump(),
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception):
        logger.exception("Unhandled error on %s", request.url.path)
        return JSONResponse(
            status_code=500,
            content=ErrorResponse(
                detail="Internal server error.",
                code="internal_error",
                request_id=getattr(request.state, "request_id", None),
            ).model_dump(),
        )

    # --- Routers -----------------------------------------------------------
    app.include_router(health.router)
    app.include_router(auth.router)
    app.include_router(oauth.router)
    app.include_router(devices.router)
    app.include_router(trust.router)
    app.include_router(resources.router)
    app.include_router(policies.router)
    app.include_router(blocked_ips.router)
    app.include_router(edr.router)
    app.include_router(pdp.router)
    app.include_router(proxy.router)
    app.include_router(signals.router)
    app.include_router(simulator.router)
    app.include_router(ai_narrator.router)
    app.include_router(audit.router)
    app.include_router(sessions.router)
    app.include_router(ws.router)
    app.include_router(users.router)
    app.include_router(alerts.router)
    app.include_router(vault.router)
    app.include_router(voice_alerts.router)
    app.include_router(dashboard.router)
    app.include_router(gateway_auth.router)
    app.include_router(scim_router.router)

    @app.get("/", tags=["meta"], summary="API index")
    def index() -> dict[str, object]:
        return {
            "name": settings.app_name,
            "version": health.VERSION,
            "docs": "/docs",
            "health": "/health",
            "trust_weights": settings.trust_weights,
            "risk_bands": {
                "LOW": f">= {settings.risk_low_min}",
                "MEDIUM": f"{settings.risk_medium_min}-{settings.risk_low_min - 1}",
                "HIGH": f"{settings.risk_high_min}-{settings.risk_medium_min - 1}",
                "CRITICAL": f"0-{settings.risk_high_min - 1}",
            },
        }

    return app


app = create_app()
