"""Enterprise error handling mappings, custom HTTP exceptions, and correlation tracers."""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import Request, Response
from fastapi.responses import JSONResponse

from src.utils.logging import get_logger

logger = get_logger(__name__)


class APIException(Exception):
    """Base exception for all enterprise API layer failures."""

    def __init__(
        self,
        message: str,
        status_code: int = 400,
        error_code: str = "BAD_REQUEST",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.error_code = error_code
        self.details = details or {}


class AuthenticationError(APIException):
    """Exception thrown during authentication failures."""

    def __init__(self, message: str = "Invalid credentials or token.") -> None:
        super().__init__(message, status_code=401, error_code="UNAUTHORIZED")


class AuthorizationError(APIException):
    """Exception thrown when access checks fail."""

    def __init__(self, message: str = "Permission denied.") -> None:
        super().__init__(message, status_code=403, error_code="FORBIDDEN")


async def global_exception_handler(request: Request, exc: Exception) -> Response:
    """Central FastAPI handler generating structured JSON errors with tracking request context."""
    correlation_id = getattr(
        request.state, "correlation_id", f"err_{uuid.uuid4().hex[:12]}"
    )

    if isinstance(exc, APIException):
        logger.warning(
            "API warning [%s]: %s (Correlation: %s)",
            exc.error_code,
            exc.message,
            correlation_id,
        )
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": {
                    "code": exc.error_code,
                    "message": exc.message,
                    "details": exc.details,
                    "correlation_id": correlation_id,
                }
            },
        )

    logger.exception("Internal Server Exception. Correlation ID: %s", correlation_id)
    return JSONResponse(
        status_code=500,
        content={
            "error": {
                "code": "INTERNAL_SERVER_ERROR",
                "message": "An unexpected error occurred. Please contact support.",
                "correlation_id": correlation_id,
            }
        },
    )
