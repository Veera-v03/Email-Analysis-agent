"""IAM Security DTOs, Role-Based Access Control (RBAC) enums, and permission maps."""

from __future__ import annotations

from enum import StrEnum
from uuid import UUID

from pydantic import Field

from src.common.models import BaseDTO


class Role(StrEnum):
    """Platform Role-Based Access Control (RBAC) roles."""

    SUPER_ADMIN = "SUPER_ADMIN"
    ADMIN = "ADMIN"
    ANALYST = "ANALYST"
    AUDITOR = "AUDITOR"


class Permission(StrEnum):
    """Granular system permission strings."""

    READ_INCIDENT = "READ_INCIDENT"
    REMEDIATE_INCIDENT = "REMEDIATE_INCIDENT"
    MANAGE_POLICY = "MANAGE_POLICY"
    MANAGE_USERS = "MANAGE_USERS"
    VIEW_AUDIT = "VIEW_AUDIT"


# RBAC Role-to-Permissions Mapping Matrix
ROLE_PERMISSIONS_MAP: dict[Role, set[Permission]] = {
    Role.SUPER_ADMIN: {
        Permission.READ_INCIDENT,
        Permission.REMEDIATE_INCIDENT,
        Permission.MANAGE_POLICY,
        Permission.MANAGE_USERS,
        Permission.VIEW_AUDIT,
    },
    Role.ADMIN: {
        Permission.READ_INCIDENT,
        Permission.REMEDIATE_INCIDENT,
        Permission.MANAGE_POLICY,
        Permission.MANAGE_USERS,
        Permission.VIEW_AUDIT,
    },
    Role.ANALYST: {
        Permission.READ_INCIDENT,
        Permission.REMEDIATE_INCIDENT,
        Permission.VIEW_AUDIT,
    },
    Role.AUDITOR: {
        Permission.READ_INCIDENT,
        Permission.VIEW_AUDIT,
    },
}


class TokenPairDTO(BaseDTO):
    """JWT Token pair response model."""

    access_token: str = Field(description="RS256 signed access token")
    refresh_token: str = Field(description="RS256 signed refresh token")
    token_type: str = Field(default="Bearer", description="Token authentication scheme")
    expires_in: int = Field(description="Access token lifespan in seconds")


class TokenPayloadDTO(BaseDTO):
    """Decoded JWT payload claims schema."""

    sub: UUID = Field(description="Subject User UUID")
    tenant_id: UUID = Field(description="Tenant UUID context")
    email: str = Field(description="User email address")
    role: Role = Field(description="Assigned user RBAC role")
    permissions: list[str] = Field(
        default_factory=list, description="Granted permission list"
    )
    token_type: str = Field(description="Token purpose: 'access' or 'refresh'")
    jti: UUID = Field(description="JWT unique ID UUID")
    exp: int = Field(description="Expiration Unix timestamp")
    iat: int = Field(description="Issued At Unix timestamp")


class AuthenticatedUser(BaseDTO):
    """Currently resolved authenticated user security context."""

    user_id: UUID = Field(description="User UUID")
    tenant_id: UUID = Field(description="Tenant UUID")
    email: str = Field(description="User email address")
    display_name: str = Field(description="Display name")
    role: Role = Field(description="RBAC role")
    permissions: list[str] = Field(
        default_factory=list, description="List of granted permissions"
    )


class LoginRequestDTO(BaseDTO):
    """User authentication login request payload."""

    email: str = Field(description="User corporate email address")
    password: str = Field(description="Cleartext account password")
    tenant_domain: str | None = Field(
        default=None, description="Optional tenant domain string"
    )


class RefreshTokenRequestDTO(BaseDTO):
    """Token refresh request payload."""

    refresh_token: str = Field(description="Valid refresh token string")
