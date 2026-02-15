from fastapi import Depends, Request

from ..services.auth import AuthService


def get_auth_service(request: Request) -> AuthService:
    return request.app.state.auth_service
