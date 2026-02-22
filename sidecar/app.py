"""
SafeLLM Sidecar - Security Gateway for LLM Applications.

Provides layered security scanning via FastAPI.
Endpoints:
    /auth      - Forward-auth for APISIX (body via X-Guard-Body header)
    /v1/guard  - Direct security check (recommended)
    /health    - Health check
    /metrics   - Prometheus metrics (RPS, latency, blocked requests) [if ENABLE_METRICS=true]

Architecture (Waterfall Pipeline):
    L0: Cache (Redis) - <0.1ms
    L1: Keywords (FlashText) - <0.01ms
    L1.5: PII (Presidio) - ~6-8ms

Features:
    - Request coalescing (dedup concurrent identical requests)
    - Circuit breaker for Redis (prevents timeout cascades)
    - Graceful shutdown with cleanup
    - Prometheus metrics (RPS, latency histograms, blocked requests counter)
    
Observability:
    Prometheus metrics are controlled by ENABLE_METRICS (default: true).
    Disabling saves CPU/RAM (no middleware for every request).
    Metrics are defined in core/telemetry.py (avoid circular imports).
    
⚠️ MULTI-WORKER NOTE:
    Circuit Breaker uses asyncio.Lock, which is per-process only.
    With multiple workers (Granian --workers 4), each worker has its own
    Circuit Breaker. The system is N× less responsive to Redis failures
    where N = number of workers. This is acceptable for most deployments.
"""
from contextlib import asynccontextmanager
from fastapi import FastAPI
import logging

from .api import auth, health, guard, dlp
from .api.dlp import audit_router
from .core.settings import Settings, get_settings
from .services.auth import AuthService
from .edition import get_edition_info

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Lifespan context manager for warmup and cleanup.
    
    Warmup Phase:
        - Pre-load models before accepting requests
        - Prevents "cold start" latency on first request
        - Validates layer health
    
    Cleanup Phase:
        - Gracefully shutdown request coalescer
        - Close Redis connections
        - Cancel pending requests
    """
    settings = app.state.settings
    service = app.state.auth_service
    
    # === WARMUP PHASE ===
    edition_info = get_edition_info()
    logger.info(
        f"Starting SafeLLM ({edition_info['edition']} edition)...",
        extra={"features": edition_info["features"]}
    )
    logger.info("Starting model warmup...")
    
    if service._pipeline:
        try:
            # Dummy request to initialize all lazy-loaded components
            await service._pipeline.execute("warmup test prompt", request_id="system-warmup")
            logger.info("Pipeline warmup complete")
        except Exception as e:
            logger.warning(f"Warmup failed (non-critical): {e}")
    
    # Check layer health
    if service._pipeline:
        health_status = await service._pipeline.health_check()
        for layer, status in health_status.items():
            logger.info(f"Layer {layer}: {'ready' if status else 'unavailable'}")
    
    logger.info("SafeLLM Sidecar ready to accept requests")
    
    yield  # Application runs here
    
    # === CLEANUP PHASE ===
    logger.info("Shutting down SafeLLM Sidecar...")
    
    # Graceful shutdown: cleanup coalescer and connections
    try:
        await service.shutdown()
        logger.info("Service shutdown complete")
    except Exception as e:
        logger.error(f"Shutdown error: {e}")


def create_app(settings: Settings | None = None) -> FastAPI:
    """
    Application factory.
    
    Creates FastAPI app with:
        - Security pipeline (waterfall layers)
        - Request coalescing (dedup concurrent requests)
        - Warmup/cleanup lifecycle
        - Prometheus metrics (/metrics endpoint)
    
    Args:
        settings: Optional settings override (for testing)
    
    Returns:
        Configured FastAPI application
    """
    cfg = settings or get_settings()
    service = AuthService(cfg)

    app = FastAPI(
        title="SafeLLM Sidecar",
        version="2.1.0",  # Release version
        description="Security Gateway for LLM Applications",
        lifespan=lifespan
    )
    app.state.settings = cfg
    app.state.auth_service = service

    # Register routers
    app.include_router(health.router)
    app.include_router(auth.router)
    app.include_router(guard.router)
    app.include_router(dlp.router)
    app.include_router(audit_router)  # DLP Audit Mode (/v1/audit/*)
    # === PROMETHEUS INSTRUMENTATION ===
    # Kontrolowane przez ENABLE_METRICS (default: true)
    # Disable via: ENABLE_METRICS=false in .env or environment variable
    #
    # Automatyczne metryki HTTP:
    #   - http_requests_total (counter)
    #   - http_request_duration_seconds (histogram)
    #   - http_requests_in_progress (gauge)
    #
    # Custom metryki SafeLLM (zdefiniowane w core/telemetry.py):
    #   - safellm_blocked_requests_total
    #   - safellm_scan_duration_seconds
    #   - safellm_prompt_length_chars
    if cfg.ENABLE_METRICS:
        from prometheus_fastapi_instrumentator import Instrumentator
        Instrumentator().instrument(app).expose(app, endpoint="/metrics")
        logger.info("Prometheus metrics enabled at /metrics")
    else:
        logger.info("Prometheus metrics disabled (ENABLE_METRICS=false)")
    
    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn
    # Development server with limits
    uvicorn.run(
        app, 
        host="0.0.0.0", 
        port=8000,
        limit_concurrency=100,      # Max concurrent connections
        limit_max_requests=10000,   # Restart after N requests (prevent memory leaks)
    )
