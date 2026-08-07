"""Identity & Access Management (IAM) and security infrastructure package."""

from __future__ import annotations

from src.security.auth_service import AuthenticationService
from src.security.dependencies import (
    get_authorization_service,
    get_current_user,
    get_token_manager,
    require_permission,
    require_role,
    verify_tenant_access,
)
from src.security.exceptions import (
    AccountLockedError,
    AuthenticationError,
    AuthorizationError,
    InvalidTokenError,
    SecurityError,
    TokenExpiredError,
)
from src.security.keys import RSAKeyManager
from src.security.models import (
    ROLE_PERMISSIONS_MAP,
    AuthenticatedUser,
    LoginRequestDTO,
    Permission,
    RefreshTokenRequestDTO,
    Role,
    TokenPairDTO,
    TokenPayloadDTO,
)
from src.security.module import IAMModule, register_iam_module
from src.security.password import PasswordHasher
from src.security.rbac import AuthorizationService
from src.security.token_manager import TokenManager, TokenRevocationManager

__all__ = [
    "AccountLockedError",
    "AuthenticatedUser",
    "AuthenticationError",
    "AuthenticationService",
    "AuthorizationError",
    "AuthorizationService",
    "IAMModule",
    "InvalidTokenError",
    "LoginRequestDTO",
    "PasswordHasher",
    "Permission",
    "ROLE_PERMISSIONS_MAP",
    "RSAKeyManager",
    "RefreshTokenRequestDTO",
    "Role",
    "SecurityError",
    "TokenExpiredError",
    "TokenManager",
    "TokenPairDTO",
    "TokenPayloadDTO",
    "TokenRevocationManager",
    "get_authorization_service",
    "get_current_user",
    "get_token_manager",
    "register_iam_module",
    "require_permission",
    "require_role",
    "verify_tenant_access",
]
