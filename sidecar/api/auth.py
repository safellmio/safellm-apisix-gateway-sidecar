"""
Auth endpoint for APISIX integration.

ARCHITECTURE: APISIX serverless-pre-function sends the body via HTTP POST
directly to this endpoint (via resty.http). No Base64 encoding,
no header size limits.

Flow:
    1. Client → APISIX (POST /api/chat with body)
    2. APISIX Lua (resty.http) → POST /auth with body
    3. Sidecar → scans body, returns 200/403
    4. APISIX → allows or blocks the request
"""
import uuid
from fastapi import APIRouter, Depends, Request, Response

from .deps import get_auth_service
from ..services.auth import AuthService
from ..core.settings import get_settings

router = APIRouter()


async def _read_body_with_limit(request: Request, max_size: int) -> tuple[bytes, bool]:
    """
    Read request body in streaming mode and stop once size exceeds limit.

    Returns:
        (body_bytes, too_large)
    """
    chunks = bytearray()
    async for chunk in request.stream():
        if not chunk:
            continue
        chunks.extend(chunk)
        if len(chunks) > max_size:
            return b"", True
    return bytes(chunks), False


@router.api_route("/auth", methods=["GET", "POST"])
async def auth(
    request: Request,
    service: AuthService = Depends(get_auth_service)
) -> Response:
    """
    Security check endpoint for APISIX.
    
    Receives body directly via HTTP POST from APISIX Lua script.
    No Base64 encoding - body is sent as-is in request payload.
    
    Returns:
        200 OK - Request allowed (with X-Latency-Ms header)
        403 Forbidden - Request blocked (with X-Blocked-By header)
        413 Entity Too Large - Body exceeds MAX_BODY_SIZE
    """
    settings = get_settings()
    request_id = request.headers.get("x-request-id", str(uuid.uuid4())[:8])
    
    # === BODY EXTRACTION ===
    # Check Content-Length before reading to prevent memory exhaustion
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            body_size = int(content_length)
        except ValueError:
            body_size = 0
        if body_size > settings.MAX_BODY_SIZE:
            return Response(
                status_code=413,
                content="Request body too large",
                headers={"X-Request-Id": request_id}
            )

    # Stream body with hard cap to prevent large in-memory allocations
    # when Content-Length is absent or unreliable (chunked transfer).
    raw_body, too_large = await _read_body_with_limit(request, settings.MAX_BODY_SIZE)
    if too_large:
        return Response(
            status_code=413,
            content="Request body too large",
            headers={"X-Request-Id": request_id}
        )
    body = raw_body.decode("utf-8", errors="replace") if raw_body else ""
    
    # Empty body = nothing to scan, allow
    if not body:
        return Response(
            status_code=200,
            headers={
                settings.ALLOW_HEADER: "allowed",
                "X-Request-Id": request_id,
                "X-Latency-Ms": "0",
                "X-Scanned-Body-Length": "0",
            },
        )
    
    # === SECURITY SCAN ===
    uri = request.headers.get("x-forwarded-uri", request.headers.get("x-original-uri", ""))
    
    result = await service.decide_async(body, uri, request_id)
    decision = result.decision
    
    # === RESPONSE ===
    if decision.allowed:
        return Response(
            status_code=200,
            headers={
                settings.ALLOW_HEADER: "allowed",
                "X-Request-Id": request_id,
                "X-Latency-Ms": str(round(result.total_latency_ms, 2)),
                "X-Scanned-Body-Length": str(len(body)),
            },
        )

    return Response(
        status_code=403,
        content=decision.reason,
        headers={
            "X-Request-Id": request_id,
            "X-Blocked-By": result.stopping_layer or "unknown",
            "X-Latency-Ms": str(round(result.total_latency_ms, 2)),
        }
    )
