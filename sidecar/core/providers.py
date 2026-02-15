"""OSS providers with safe fallbacks."""
from __future__ import annotations

from ..services.request_coalescer import RequestCoalescer
from ..layers.pii_fast import PIILayer
from .settings import Settings


def get_ai_guard_layer(settings: Settings):
    """AI guard is not available in OSS."""
    return None


def get_request_coalescer(settings: Settings):
    """
    Return coalescer instance and distributed flag (always False in OSS).
    """
    return (
        RequestCoalescer(
            max_pending=1000,
            cleanup_interval=60,
        ),
        False,
    )


def get_pii_layer(settings: Settings):
    """Return PII layer (fast regex only in OSS)."""
    if not settings.ENABLE_L3_PII:
        return None

    # USE_FAST_PII=true enables regex PII detection. 
    # USE_FAST_PII=false disables PII layer in OSS (GLiNER unavailable).
    if not settings.USE_FAST_PII:
        return None

    return PIILayer(
        entities=settings.L3_PII_ENTITIES,
        threshold=settings.L3_PII_THRESHOLD,
        use_fast=True,
    )


def cleanup_ai_guard_models() -> None:
    """No-op in OSS."""
    return


async def log_audit_event(
    request_id: str,
    prompt: str,
    allowed: bool,
    layer: str,
    reason: str,
    latency_ms: float,
) -> None:
    """No-op in OSS."""
    return
