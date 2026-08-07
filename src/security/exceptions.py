"""IAM security exception hierarchy for ScamON Enterprise."""

from __future__ import annotations

from typing import Any

from src.common.exceptions import ScamONError


class SecurityError(ScamONError):
    """Base exception for all security and IAM errors."""

    def __init__(
        self,
        message: str,
        error_code: str = "ERR_SECURITY_FAILED",
        status_code: int = 401,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            message=message,
            error_code=error_code,
            status_code=status_code,
            details=details,
        )


class AuthenticationError(SecurityError):
    """Raised when authentication credentials or tokens are invalid."""

    def __init__(
        self,
        message: str = "Authentication failed",
        error_code: str = "ERR_AUTHENTICATION_FAILED",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            message=message,
            error_code=error_code,
            status_code=401,
            details=details,
        )


class TokenExpiredError(AuthenticationError):
    """Raised when an access or refresh token has expired."""

    def __init__(
        self,
        message: str = "Token has expired",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            message=message,
            error_code="ERR_TOKEN_EXPIRED",
            details=details,
        )


class InvalidTokenError(AuthenticationError):
    """Raised when a JWT token signature or claims validation fails."""

    def __init__(
        self,
        message: str = "Invalid token signature or payload",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            message=message,
            error_code="ERR_INVALID_TOKEN",
            details=details,
        )


class AuthorizationError(SecurityError):
    """Raised when an authenticated user lacks required roles or permissions."""

    def __init__(
        self,
        message: str = "Permission denied",
        error_code: str = "ERR_PERMISSION_DENIED",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            message=message,
            error_code=error_code,
            status_code=403,
            details=details,
        )


class AccountLockedError(AuthenticationError):
    """Raised when an account is locked due to consecutive failed login attempts."""

    def __init__(
        self,
        message: str = "Account locked due to excessive failed login attempts",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            message=message,
            error_code="ERR_ACCOUNT_LOCKED",
            details=details,
        )
