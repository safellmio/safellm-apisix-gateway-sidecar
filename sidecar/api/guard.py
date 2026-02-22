"""
Direct /v1/guard endpoint - bypasses APISIX forward-auth body issue.

This endpoint receives the full request body directly, avoiding the
forward-auth plugin limitation where body is not forwarded.

Usage:
    POST /v1/guard
    {
        "text": "User prompt to check",
        "metadata": {"user_id": "123"}
    }
    
Response:
    {
        "safe": true,
        "score": 0.0,
        "reason": null,
        "layer": "PASSED_ALL",
        "latency_ms": 1.23
    }

Security:
    - Body size limit enforced via Pydantic validator
    - Text length limit prevents memory exhaustion
    - Rate limiting via APISIX config (recommended)
"""
import uuid
from typing import Any

from fastapi import APIRouter, Depends, Request, HTTPException
from pydantic import BaseModel, field_validator

from .deps import get_auth_service, require_management_api_key
from ..services.auth import AuthService
from ..core.settings import get_settings

router = APIRouter(prefix="/v1", tags=["guard"])

# Max text length (characters) - prevent memory exhaustion
# 1MB in UTF-8 can be ~250K-1M characters depending on encoding
MAX_TEXT_LENGTH = 100_000  # 100K characters ≈ ~400KB worst case


class GuardRequest(BaseModel):
    """
    Input for security check.
    
    Validates:
        - text: Required, max 100K characters
        - metadata: Optional dict for correlation/tracking
    """
    text: str
    metadata: dict[str, Any] = {}
    
    @field_validator("text")
    @classmethod
    def validate_text_length(cls, v: str) -> str:
        """Validate text length to prevent memory exhaustion."""
        if len(v) > MAX_TEXT_LENGTH:
            raise ValueError(
                f"Text too long: {len(v)} chars. Max: {MAX_TEXT_LENGTH}"
            )
        if not v.strip():
            raise ValueError("Text cannot be empty")
        return v


class GuardResponse(BaseModel):
    """Security check result."""
    safe: bool
    score: float = 0.0
    reason: str | None = None
    layer: str | None = None
    latency_ms: float = 0.0
    text_length: int = 0


@router.post("/guard", response_model=GuardResponse)
async def guard(
    payload: GuardRequest,
    request: Request,
    service: AuthService = Depends(get_auth_service)
) -> GuardResponse:
    """
    Check text for security issues.
    
    Executes the full security pipeline:
    1. L0: Cache lookup (<0.1ms)
    2. L1: Keyword detection (<1ms)
    3. L1.5: PII detection (~6-8ms) [if enabled]
    4. L2: AI model analysis (~30-70ms) [if enabled]
    
    Returns immediately on first unsafe detection (short-circuit).
    
    Security:
        - Text length validated by Pydantic (max 100K chars)
        - Body size should be limited at APISIX/nginx level
        - Rate limiting recommended via APISIX limit-req plugin
    """
    settings = get_settings()
    
    # Content-Length check jako dodatkowa warstwa (defense in depth)
    # Primary protection lives in the Pydantic validator
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > settings.MAX_BODY_SIZE:
                raise HTTPException(
                    status_code=413,
                    detail=f"Request body too large. Max: {settings.MAX_BODY_SIZE} bytes"
                )
        except ValueError:
            pass  # Invalid content-length header, ignore
    
    # Generate request ID for correlation
    request_id = request.headers.get("x-request-id", uuid.uuid4().hex[:16])
    
    # Execute pipeline (with request coalescing)
    result = await service.decide_async(
        body=payload.text,
        uri="",
        request_id=request_id
    )
    
    return GuardResponse(
        safe=result.decision.allowed,
        score=0.0,  # Score is in individual layer results
        reason=result.decision.reason if not result.decision.allowed else None,
        layer=result.stopping_layer,
        latency_ms=round(result.total_latency_ms, 2),
        text_length=len(payload.text)
    )


@router.get("/guard/health")
async def guard_health(
    _auth: bool = Depends(require_management_api_key),
    service: AuthService = Depends(get_auth_service)
) -> dict:
    """Check health of security layers."""
    if service._pipeline:
        layers_health = await service._pipeline.health_check()
        all_healthy = all(layers_health.values())
        return {
            "status": "healthy" if all_healthy else "degraded",
            "layers": layers_health
        }
    return {"status": "healthy", "layers": {}}


@router.get("/guard/stats")
async def guard_stats(
    _auth: bool = Depends(require_management_api_key),
    service: AuthService = Depends(get_auth_service)
) -> dict:
    """
    Get service statistics.
    
    Includes:
        - Request coalescer stats (pending requests)
        - Cache stats (hit/miss rate)
        - Pipeline info (enabled layers)
    """
    return service.get_stats()
