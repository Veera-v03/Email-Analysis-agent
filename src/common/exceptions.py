"""Standard exception hierarchy for ScamON Enterprise."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any


class ScamONError(Exception):
    """Base exception class for all ScamON Enterprise errors."""

    def __init__(
        self,
        message: str,
        error_code: str = "ERR_INTERNAL_ERROR",
        status_code: int = 500,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.status_code = status_code
        self.details = details or {}
        self.timestamp = datetime.now(UTC)

    def to_dict(self) -> dict[str, Any]:
        """Convert exception metadata to standardized API error response format."""
        return {
            "error": {
                "code": self.error_code,
                "message": self.message,
                "status": self.status_code,
                "details": self.details,
                "timestamp": self.timestamp.isoformat(),
            }
        }


class ConfigurationError(ScamONError):
    """Raised when application configuration or settings are invalid."""

    def __init__(
        self,
        message: str,
        error_code: str = "ERR_CONFIG_INVALID",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            message=message,
            error_code=error_code,
            status_code=500,
            details=details,
        )


class ValidationError(ScamONError):
    """Raised when data input or payload fails schema validation."""

    def __init__(
        self,
        message: str,
        error_code: str = "ERR_VALIDATION_FAILED",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            message=message,
            error_code=error_code,
            status_code=400,
            details=details,
        )


class ResourceNotFoundError(ScamONError):
    """Raised when a requested resource or entity does not exist."""

    def __init__(
        self,
        message: str,
        error_code: str = "ERR_RESOURCE_NOT_FOUND",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            message=message,
            error_code=error_code,
            status_code=404,
            details=details,
        )


class DependencyError(ScamONError):
    """Raised when an external dependency or service call fails."""

    def __init__(
        self,
        message: str,
        error_code: str = "ERR_DEPENDENCY_FAILED",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            message=message,
            error_code=error_code,
            status_code=502,
            details=details,
        )


class ServiceUnavailableError(ScamONError):
    """Raised when a required service or system component is unavailable."""

    def __init__(
        self,
        message: str,
        error_code: str = "ERR_SERVICE_UNAVAILABLE",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            message=message,
            error_code=error_code,
            status_code=503,
            details=details,
        )


class RateLimitExceededError(ScamONError):
    """Raised when rate limiting thresholds are exceeded."""

    def __init__(
        self,
        message: str,
        error_code: str = "ERR_RATE_LIMIT_EXCEEDED",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            message=message,
            error_code=error_code,
            status_code=429,
            details=details,
        )


class SecurityViolationError(ScamONError):
    """Raised when access control or security policies are violated."""

    def __init__(
        self,
        message: str,
        error_code: str = "ERR_SECURITY_VIOLATION",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            message=message,
            error_code=error_code,
            status_code=403,
            details=details,
        )


class AuthenticationError(ScamONError):
    """Raised when authentication credentials are missing, invalid, or expired."""

    def __init__(
        self,
        message: str,
        error_code: str = "ERR_UNAUTHORIZED",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            message=message,
            error_code=error_code,
            status_code=401,
            details=details,
        )


class ModuleLifecycleError(ScamONError):
    """Raised when a module fails to initialize, register, or shut down."""

    def __init__(
        self,
        message: str,
        error_code: str = "ERR_MODULE_LIFECYCLE_FAILED",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            message=message,
            error_code=error_code,
            status_code=500,
            details=details,
        )
