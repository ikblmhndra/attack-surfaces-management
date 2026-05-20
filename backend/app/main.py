"""
ASM Platform — FastAPI Application Entry Point
"""
import time
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from prometheus_fastapi_instrumentator import Instrumentator

from app.api.v1.router import api_router
from app.core.config import settings
from app.core.database import init_db, close_db
from app.core.redis_client import init_redis, close_redis
from app.core.rabbitmq import init_rabbitmq, close_rabbitmq
from app.core.opensearch import init_opensearch, close_opensearch
from app.core.logging import setup_logging
from app.core.minio_client import init_minio

log = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: startup and shutdown events."""
    setup_logging()
    log.info("ASM Platform starting", version=settings.VERSION, env=settings.ENVIRONMENT)

    # Initialize all connections
    await init_db()
    await init_redis()
    await init_rabbitmq()
    await init_opensearch()
    await init_minio()

    log.info("All services initialized successfully")
    yield

    # Cleanup
    await close_db()
    await close_redis()
    await close_rabbitmq()
    await close_opensearch()
    log.info("ASM Platform shutdown complete")


def create_application() -> FastAPI:
    app = FastAPI(
        title="ASM Platform API",
        description="Attack Surface Management & External Security Posture Management Platform",
        version=settings.VERSION,
        docs_url="/api/docs" if settings.ENVIRONMENT != "production" else None,
        redoc_url="/api/redoc" if settings.ENVIRONMENT != "production" else None,
        openapi_url="/api/openapi.json" if settings.ENVIRONMENT != "production" else None,
        lifespan=lifespan,
    )

    # ── Middleware ────────────────────────────────────────────
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.ALLOWED_ORIGINS,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
        allow_headers=["*"],
        expose_headers=["X-Request-ID", "X-Rate-Limit-Remaining"],
    )
    app.add_middleware(GZipMiddleware, minimum_size=1000)

    if settings.ENVIRONMENT == "production":
        app.add_middleware(
            TrustedHostMiddleware,
            allowed_hosts=settings.TRUSTED_HOSTS,
        )

    # ── Request ID + timing middleware ────────────────────────
    @app.middleware("http")
    async def request_middleware(request: Request, call_next):
        request_id = request.headers.get("X-Request-ID", f"req-{time.time_ns()}")
        start_time = time.time()

        with structlog.contextvars.bound_contextvars(
            request_id=request_id,
            method=request.method,
            path=request.url.path,
            client_ip=request.client.host if request.client else "unknown",
        ):
            response = await call_next(request)
            duration_ms = round((time.time() - start_time) * 1000, 2)

            response.headers["X-Request-ID"] = request_id
            response.headers["X-Response-Time"] = f"{duration_ms}ms"

            log.info(
                "request",
                status=response.status_code,
                duration_ms=duration_ms,
            )
            return response

    # ── Prometheus metrics ────────────────────────────────────
    Instrumentator(
        should_group_status_codes=True,
        should_ignore_untemplated=True,
        should_respect_env_var=True,
        should_instrument_requests_inprogress=True,
        excluded_handlers=["/health", "/metrics"],
        env_var_name="ENABLE_METRICS",
    ).instrument(app).expose(app, endpoint="/metrics", include_in_schema=False)

    # ── Routes ────────────────────────────────────────────────
    app.include_router(api_router, prefix="/api/v1")

    # ── Health check ──────────────────────────────────────────
    @app.get("/health", tags=["health"], include_in_schema=False)
    async def health_check():
        return {
            "status": "healthy",
            "version": settings.VERSION,
            "environment": settings.ENVIRONMENT,
            "timestamp": time.time(),
        }

    # ── Global exception handlers ─────────────────────────────
    @app.exception_handler(404)
    async def not_found_handler(request: Request, exc):
        detail = exc.detail if hasattr(exc, "detail") else "Resource not found"
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"detail": detail, "path": str(request.url)},
        )

    @app.exception_handler(500)
    async def server_error_handler(request: Request, exc):
        log.error("unhandled_exception", error=str(exc), exc_info=True)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": "Internal server error"},
        )

    return app


app = create_application()
