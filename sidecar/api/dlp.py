"""
DLP (Data Loss Prevention) API - Output Scanning Endpoints.

Scans LLM responses for PII/sensitive data before returning to client.

Two Architecture Modes (DLP_STREAMING_MODE):

1. BLOCK Mode (default, for banks/fintechs):
    - APISIX buffers response (body_filter_by_lua)
    - APISIX sends buffered response to /v1/scan/output
    - If PII detected: block/anonymize/log
    - Cost: Higher TTFT (Time To First Token)
    
2. AUDIT Mode (for SaaS/startups):
    - APISIX streams response directly to client (zero latency overhead)
    - APISIX http-logger plugin asynchronously sends request+response to /v1/audit/ingest
    - Sidecar scans in background, logs PII detections for audit
    - Cost: Zero latency, but PII detection is post-factum (does not block!)

Endpoints:
    POST /v1/scan/output     - Synchronous scan (for block mode)
    POST /v1/audit/ingest    - Async batch ingest (for audit mode)
    GET  /v1/scan/output/health
    GET  /v1/audit/stats     - Audit mode statistics

Usage (block mode):
    POST /v1/scan/output
    {"text": "LLM response", "request_id": "abc123"}
    
Usage (audit mode - APISIX http-logger):
    POST /v1/audit/ingest
    [{"request": {...}, "response": {...}, "route_id": "..."}]

Edition Gating:
    - OSS: Only audit mode (DLP_MODE=log) - no blocking/anonymizing
    - Enterprise: Full DLP (block, anonymize, log modes)
"""
import uuid
from typing import Optional
import logging
import asyncio

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator

from ..core.settings import get_settings
from ..core.telemetry import DLP_AUDIT_TRUNCATIONS
from ..edition import is_feature_available, get_edition
from ..layers.dlp import DLPScanner
from .deps import require_management_api_key

_dlp_logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/scan", tags=["dlp"])


def _get_max_output_length() -> int:
    """Get max output length from settings (cached)."""
    try:
        return get_settings().DLP_MAX_OUTPUT_LENGTH
    except Exception:
        return 500_000  # Fallback default


class OutputScanRequest(BaseModel):
    """
    Input for DLP output scanning.
    
    Fields:
        - text: LLM response to scan (required)
        - request_id: Correlation ID (optional, auto-generated)
    """
    text: str
    request_id: Optional[str] = None
    
    @field_validator("text")
    @classmethod
    def validate_text_length(cls, v: str) -> str:
        """Validate text length against DLP_MAX_OUTPUT_LENGTH setting."""
        max_length = _get_max_output_length()
        if len(v) > max_length:
            raise ValueError(
                f"Output too long: {len(v)} chars. Max: {max_length}"
            )
        return v


class OutputScanResponse(BaseModel):
    """DLP scan result."""
    safe: bool
    text: str  # Modified or original text
    pii_detected: bool
    entities_count: int = 0
    blocked: bool = False
    blocked_reason: Optional[str] = None
    latency_ms: float = 0.0
    mode: str = "block"


# Lazy-loaded DLP scanner instance
_dlp_scanner: Optional[DLPScanner] = None


def _get_effective_dlp_mode(requested_mode: str) -> str:
    """
    Get effective DLP mode with edition gating.
    
    OSS edition only allows 'log' mode (audit).
    Enterprise allows all modes (block, anonymize, log).
    
    Args:
        requested_mode: Mode from settings (block/anonymize/log)
        
    Returns:
        Effective mode after edition gating
    """
    # Check if block/anonymize mode is available (Enterprise only)
    if requested_mode in ("block", "anonymize"):
        if not is_feature_available("dlp_block_mode"):
            _dlp_logger.warning(
                f"DLP_MODE={requested_mode} requires Enterprise edition. "
                f"Current edition: {get_edition()}. "
                f"Falling back to 'log' mode (audit only). "
                f"For full DLP: https://safellm.io/enterprise"
            )
            return "log"
    
    return requested_mode


def get_dlp_scanner() -> DLPScanner:
    """Get or create DLP scanner instance with edition-aware mode."""
    global _dlp_scanner
    
    # In production, we use a singleton. 
    # In tests, we might want to recreate it if settings changed.
    settings = get_settings()
    
    # Apply edition gating to DLP mode
    effective_mode = _get_effective_dlp_mode(settings.DLP_MODE)
    
    if _dlp_scanner is None:
        _dlp_scanner = DLPScanner(
            mode=effective_mode,
            entities=settings.DLP_PII_ENTITIES,
            threshold=settings.DLP_PII_THRESHOLD,
            block_message=settings.DLP_BLOCK_MESSAGE,
            fail_open=settings.DLP_FAIL_OPEN,
        )
    else:
        # Check if settings changed (useful for tests)
        # Compare against effective mode, not raw settings
        if (
            _dlp_scanner._mode != effective_mode.lower() or
            _dlp_scanner._entities != settings.DLP_PII_ENTITIES or
            _dlp_scanner._threshold != settings.DLP_PII_THRESHOLD or
            _dlp_scanner._block_message != settings.DLP_BLOCK_MESSAGE or
            _dlp_scanner._fail_open != settings.DLP_FAIL_OPEN
        ):
            _dlp_scanner = DLPScanner(
                mode=effective_mode,
                entities=settings.DLP_PII_ENTITIES,
                threshold=settings.DLP_PII_THRESHOLD,
                block_message=settings.DLP_BLOCK_MESSAGE,
                fail_open=settings.DLP_FAIL_OPEN,
            )
    
    return _dlp_scanner


@router.post("/output", response_model=OutputScanResponse)
async def scan_output(payload: OutputScanRequest) -> OutputScanResponse:
    """
    Scan LLM output for PII/sensitive data.
    
    This endpoint is called by APISIX body_filter_by_lua after buffering
    the complete LLM response.
    
    Modes (configured via DLP_MODE env var):
        - block: Replace entire response if PII detected
        - anonymize: Replace PII with [REDACTED:TYPE] placeholders
        - log: Allow response but log for audit
    
    Returns:
        - safe: Whether response can be returned as-is
        - text: Modified text (if blocking/anonymizing) or original
        - pii_detected: Whether any PII was found
        - blocked: Whether response was blocked entirely
        - latency_ms: Scan duration
    """
    settings = get_settings()
    
    # Check if DLP is enabled
    if not settings.ENABLE_DLP:
        # DLP disabled - pass through without scanning
        return OutputScanResponse(
            safe=True,
            text=payload.text,
            pii_detected=False,
            entities_count=0,
            latency_ms=0.0,
            mode="disabled"
        )
    
    # Get or create scanner
    scanner = get_dlp_scanner()
    
    # Scan output
    result = await scanner.scan_output(payload.text)
    
    # Determine response text
    if result.modified_text is not None:
        response_text = result.modified_text
    else:
        response_text = payload.text
    
    # Use effective mode (after edition gating) for response
    effective_mode = _get_effective_dlp_mode(settings.DLP_MODE)
    
    return OutputScanResponse(
        safe=result.safe,
        text=response_text,
        pii_detected=result.pii_detected,
        entities_count=len(result.entities),
        blocked=not result.safe and effective_mode == "block",
        blocked_reason=result.blocked_reason,
        latency_ms=round(result.latency_ms, 2),
        mode=effective_mode
    )


@router.get("/output/health")
async def dlp_health() -> dict:
    """Check DLP scanner health."""
    settings = get_settings()
    
    # Get effective mode after edition gating
    effective_mode = _get_effective_dlp_mode(settings.DLP_MODE)
    mode_downgraded = effective_mode != settings.DLP_MODE.lower()
    
    if not settings.ENABLE_DLP:
        return {
            "status": "disabled",
            "enabled": False,
            "mode": effective_mode,
            "requested_mode": settings.DLP_MODE if mode_downgraded else None,
            "edition": get_edition(),
        }
    
    scanner = get_dlp_scanner()
    is_healthy = await scanner.health_check()
    status = scanner.get_status()
    
    response = {
        "status": "healthy" if is_healthy else "unhealthy",
        "enabled": True,
        "streaming_mode": settings.DLP_STREAMING_MODE,
        "edition": get_edition(),
        **status
    }
    
    # Add warning if mode was downgraded due to edition
    if mode_downgraded:
        response["requested_mode"] = settings.DLP_MODE
        response["edition_notice"] = (
            f"DLP_MODE={settings.DLP_MODE} requires Enterprise. "
            f"Using 'log' mode. See: https://safellm.io/enterprise"
        )
    
    return response


# =============================================================================
# AUDIT MODE - Asynchronous PII Detection (for DLP_STREAMING_MODE=audit)
# =============================================================================

# Audit router (separate prefix for clarity)
audit_router = APIRouter(prefix="/v1/audit", tags=["audit"])

import logging
from datetime import datetime, timezone
import hashlib

logger = logging.getLogger(__name__)

# In-memory audit stats (can be extended to Redis for multi-worker)
_audit_stats = {
    "total_ingested": 0,
    "pii_detected": 0,
    "entities_by_type": {},
    "last_ingest_time": None,
}
_audit_stats_lock = asyncio.Lock()


def reset_audit_stats():
    """Reset audit stats for testing."""
    global _audit_stats
    _audit_stats = {
        "total_ingested": 0,
        "pii_detected": 0,
        "entities_by_type": {},
        "last_ingest_time": None,
    }


class AuditIngestItem(BaseModel):
    """
    Single item from APISIX http-logger batch.

    Supports both flat format (request_body/response_body) and
    APISIX http-logger nested format (request.body/response.body).
    """
    # Flat format fields (legacy/direct API)
    request_id: Optional[str] = None
    route_id: Optional[str] = None
    client_ip: Optional[str] = None
    request_body: Optional[str] = None
    response_body: Optional[str] = None
    upstream_latency: Optional[float] = None
    timestamp: Optional[str] = None

    # APISIX http-logger nested format
    request: Optional[dict] = None
    response: Optional[dict] = None

    def model_post_init(self, __context) -> None:
        """Extract body from nested request/response if flat fields are empty."""
        # Handle nested request.body from http-logger
        if self.request_body is None and self.request and isinstance(self.request, dict):
            self.request_body = self.request.get("body")

        # Handle nested response.body from http-logger
        if self.response_body is None and self.response and isinstance(self.response, dict):
            body = self.response.get("body")
            if body is not None:
                # Validate and truncate if needed
                max_length = _get_max_output_length()
                if len(body) > max_length:
                    _dlp_logger.warning(
                        f"Audit item response_body truncated: {len(body)} -> {max_length} chars"
                    )
                    if DLP_AUDIT_TRUNCATIONS is not None:
                        DLP_AUDIT_TRUNCATIONS.inc()
                    body = body[:max_length]
                self.response_body = body

        # Extract route_id from nested if not set
        if self.route_id is None and self.request and isinstance(self.request, dict):
            self.route_id = self.request.get("route_id")

    @field_validator("response_body")
    @classmethod
    def validate_response_body_length(cls, v: Optional[str]) -> Optional[str]:
        """
        Validate response_body length against DLP_MAX_OUTPUT_LENGTH.

        Prevents multi-megabyte payloads from overwhelming the scanner.
        Truncates to max length instead of rejecting (audit mode is best-effort).
        """
        if v is None:
            return v
        max_length = _get_max_output_length()
        if len(v) > max_length:
            _dlp_logger.warning(
                f"Audit item response_body truncated: {len(v)} -> {max_length} chars"
            )
            if DLP_AUDIT_TRUNCATIONS is not None:
                DLP_AUDIT_TRUNCATIONS.inc()
            return v[:max_length]
        return v


class AuditIngestRequest(BaseModel):
    """Batch of audit logs from APISIX http-logger."""
    items: list[AuditIngestItem] = []
    
    @field_validator("items", mode="before")
    @classmethod
    def parse_items(cls, v):
        """Handle both list and single item."""
        if isinstance(v, dict):
            return [v]
        return v


class AuditIngestResponse(BaseModel):
    """Response for audit ingest."""
    ingested: int
    pii_detected: int
    processing_time_ms: float


@audit_router.post("/ingest", response_model=AuditIngestResponse)
async def audit_ingest(
    payload: list[AuditIngestItem] | AuditIngestRequest
) -> AuditIngestResponse:
    """
    Asynchronously ingest LLM request/response logs for PII scanning.
    
    Called by APISIX http-logger plugin in batches (non-blocking).
    
    This endpoint is for AUDIT mode only - it scans but does NOT block.
    PII detections are logged for compliance/audit review.
    
    Flow:
        1. http-logger collects request+response asynchronously
        2. Sends batch to /v1/audit/ingest (this endpoint)
        3. We scan each response_body for PII
        4. Log detections to audit log (via existing audit system)
        5. Return stats (non-blocking, client already received response)
    
    Returns:
        - ingested: Number of items processed
        - pii_detected: How many had PII
        - processing_time_ms: Total scan time
    """
    import time
    start = time.perf_counter()
    
    settings = get_settings()
    items = payload if isinstance(payload, list) else payload.items
    pii_detected_count = 0
    
    # If DLP is disabled, still count the ingested items but don't scan for PII
    if not settings.ENABLE_DLP:
        async with _audit_stats_lock:
            _audit_stats["total_ingested"] += len(items)
            _audit_stats["last_ingest_time"] = datetime.now(timezone.utc).isoformat()
        return AuditIngestResponse(
            ingested=len(items),
            pii_detected=0,
            processing_time_ms=0.0
        )
    
    scanner = get_dlp_scanner()
    
    for item in items:
        # Scan response body for PII
        if item.response_body:
            try:
                result = await scanner.scan_output(item.response_body)
                
                if result.pii_detected:
                    pii_detected_count += 1
                    
                    # Update stats
                    for entity in result.entities:
                        entity_type = entity.get("entity_type", "UNKNOWN")
                        async with _audit_stats_lock:
                            _audit_stats["entities_by_type"][entity_type] = (
                                _audit_stats["entities_by_type"].get(entity_type, 0) + 1
                            )
                    
                    # Log for audit (hash response, don't log raw PII!)
                    response_hash = hashlib.sha256(
                        item.response_body.encode()
                    ).hexdigest()[:16]
                    
                    logger.warning(
                        f"AUDIT: PII detected in response | "
                        f"request_id={item.request_id} | "
                        f"route={item.route_id} | "
                        f"client={item.client_ip} | "
                        f"response_hash={response_hash} | "
                        f"entities={[e['entity_type'] for e in result.entities]}"
                    )
                    
            except Exception as e:
                logger.error(f"Audit scan error: {e}")
    
    # Update global stats
    async with _audit_stats_lock:
        _audit_stats["total_ingested"] += len(items)
        _audit_stats["pii_detected"] += pii_detected_count
        _audit_stats["last_ingest_time"] = datetime.now(timezone.utc).isoformat()
    
    elapsed_ms = (time.perf_counter() - start) * 1000
    
    return AuditIngestResponse(
        ingested=len(items),
        pii_detected=pii_detected_count,
        processing_time_ms=round(elapsed_ms, 2)
    )


@audit_router.get("/stats")
async def audit_stats(
    _auth: bool = Depends(require_management_api_key),
) -> dict:
    """
    Get audit mode statistics.
    
    Returns cumulative stats since last restart:
        - total_ingested: Total request/response pairs processed
        - pii_detected: How many had PII
        - entities_by_type: Breakdown by PII type
        - last_ingest_time: When last batch was processed
    """
    settings = get_settings()
    effective_mode = _get_effective_dlp_mode(settings.DLP_MODE)
    
    async with _audit_stats_lock:
        stats_snapshot = {
            "total_ingested": _audit_stats["total_ingested"],
            "pii_detected": _audit_stats["pii_detected"],
            "entities_by_type": dict(_audit_stats["entities_by_type"]),
            "last_ingest_time": _audit_stats["last_ingest_time"],
        }
    return {
        "streaming_mode": settings.DLP_STREAMING_MODE,
        "enabled": settings.ENABLE_DLP,
        "edition": get_edition(),
        "effective_mode": effective_mode,
        **stats_snapshot,
    }


@audit_router.get("/health")
async def audit_health(
    _auth: bool = Depends(require_management_api_key),
) -> dict:
    """Check audit mode health."""
    settings = get_settings()
    effective_mode = _get_effective_dlp_mode(settings.DLP_MODE)
    
    return {
        "status": "healthy",
        "streaming_mode": settings.DLP_STREAMING_MODE,
        "enabled": settings.ENABLE_DLP,
        "mode": effective_mode,
        "edition": get_edition(),
        "dlp_block_available": is_feature_available("dlp_block_mode"),
    }
