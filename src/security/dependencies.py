"""FastAPI security dependencies and context resolvers."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any
from uuid import UUID

from src.container.di import container
from src.security.models import (
    AuthenticatedUser,
    Permission,
    Role,
    TokenPayloadDTO,
)
from src.security.rbac import AuthorizationService
from src.security.token_manager import TokenManager


def get_token_manager() -> TokenManager:
    """Resolve central TokenManager singleton from Container or instantiate."""
    if container.has(TokenManager):
        return container.resolve(TokenManager)
    return TokenManager()


def get_authorization_service() -> AuthorizationService:
    """Resolve central AuthorizationService singleton from Container or instantiate."""
    if container.has(AuthorizationService):
        return container.resolve(AuthorizationService)
    return AuthorizationService()


def get_current_user(token: str) -> AuthenticatedUser:
    """Resolve AuthenticatedUser context from Bearer JWT access token."""
    token_mgr = get_token_manager()
    payload: TokenPayloadDTO = token_mgr.decode_token(token, expected_type="access")

    return AuthenticatedUser(
        user_id=payload.sub,
        tenant_id=payload.tenant_id,
        email=payload.email,
        display_name=payload.email.split("@")[0].title(),
        role=payload.role,
        permissions=payload.permissions,
    )


def require_permission(
    permission: Permission | str,
) -> Callable[[AuthenticatedUser], Any]:
    """Dependency factory enforcing specific granular permission."""

    async def _dependency(
        current_user: AuthenticatedUser,
    ) -> AuthenticatedUser:
        auth_service = get_authorization_service()
        await auth_service.authorize_permission(current_user, permission)
        return current_user

    return _dependency


def require_role(
    allowed_roles: list[Role | str],
) -> Callable[[AuthenticatedUser], AuthenticatedUser]:
    """Dependency factory enforcing allowed RBAC roles."""

    def _dependency(current_user: AuthenticatedUser) -> AuthenticatedUser:
        auth_service = get_authorization_service()
        auth_service.authorize_role(current_user, allowed_roles)
        return current_user

    return _dependency


def verify_tenant_access(
    current_user: AuthenticatedUser, resource_tenant_id: UUID
) -> None:
    """Helper enforcing tenant boundary checks."""
    auth_service = get_authorization_service()
    auth_service.verify_tenant_isolation(current_user, resource_tenant_id)
