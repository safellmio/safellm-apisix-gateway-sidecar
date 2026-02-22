import hmac
from fastapi import Depends, Header, HTTPException, Request

from ..services.auth import AuthService
from ..core.settings import get_settings


def get_auth_service(request: Request) -> AuthService:
    return request.app.state.auth_service


def require_management_api_key(
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
) -> bool:
    """
    Optional API key guard for management endpoints.
    If MANAGEMENT_API_KEY is unset, endpoint remains open.
    """
    settings = get_settings()
    configured = settings.MANAGEMENT_API_KEY
    if configured is None:
        return True
    expected = configured.get_secret_value()
    if not x_api_key or not hmac.compare_digest(x_api_key, expected):
        raise HTTPException(status_code=401, detail="Invalid management API key")
    return True
