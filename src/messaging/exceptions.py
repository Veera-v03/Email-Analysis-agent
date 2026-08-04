"""Messaging system exception hierarchy for ScamON Enterprise."""

from __future__ import annotations

from typing import Any

from src.common.exceptions import ScamONError


class MessagingError(ScamONError):
    """Base exception for all messaging bus errors."""

    def __init__(
        self,
        message: str,
        error_code: str = "ERR_MESSAGING_FAILED",
        status_code: int = 500,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            message=message,
            error_code=error_code,
            status_code=status_code,
            details=details,
        )


class EventDispatchError(MessagingError):
    """Raised when an event dispatch to subscriber fails."""

    def __init__(
        self,
        message: str,
        error_code: str = "ERR_EVENT_DISPATCH_FAILED",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            message=message,
            error_code=error_code,
            status_code=500,
            details=details,
        )


class SubscriberNotFoundError(MessagingError):
    """Raised when no subscribers are found for an event requiring handling."""

    def __init__(
        self,
        message: str,
        error_code: str = "ERR_SUBSCRIBER_NOT_FOUND",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            message=message,
            error_code=error_code,
            status_code=404,
            details=details,
        )


class MiddlewareError(MessagingError):
    """Raised when a messaging middleware pipeline execution fails."""

    def __init__(
        self,
        message: str,
        error_code: str = "ERR_MIDDLEWARE_FAILED",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            message=message,
            error_code=error_code,
            status_code=500,
            details=details,
        )
