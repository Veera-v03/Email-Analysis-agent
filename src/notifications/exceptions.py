"""Domain exceptions for Module 20 Enterprise SOC Alerting and Multi-Channel Notification Engine."""

from __future__ import annotations

from typing import Any

from src.common.exceptions import ScamONError


class NotificationError(ScamONError):
    """Base exception for all Module 20 notification and dispatch failures."""

    def __init__(
        self,
        message: str = "Notification dispatch failed.",
        error_code: str = "ERR_NOTIFICATION_FAILED",
        status_code: int = 500,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            message=message,
            error_code=error_code,
            status_code=status_code,
            details=details or {},
        )


class ChannelDeliveryError(NotificationError):
    """Raised when an outbound notification channel fails to deliver payload."""

    def __init__(
        self,
        channel: str,
        message: str = "Channel delivery failed.",
        details: dict[str, Any] | None = None,
    ) -> None:
        merged_details = details or {}
        merged_details["channel"] = channel
        super().__init__(
            message=f"[{channel.upper()}] {message}",
            error_code=f"ERR_{channel.upper()}_DELIVERY_FAILED",
            status_code=502,
            details=merged_details,
        )


class SSRFSecurityError(NotificationError):
    """Raised when a webhook URL fails SSRF protection checks (private/loopback/metadata IP)."""

    def __init__(
        self,
        url: str,
        reason: str = "Destination IP is blocked by SSRF security policy.",
        details: dict[str, Any] | None = None,
    ) -> None:
        merged_details = details or {}
        merged_details["url"] = url
        merged_details["reason"] = reason
        super().__init__(
            message=f"SSRF Security Violation for webhook '{url}': {reason}",
            error_code="ERR_SSRF_VIOLATION",
            status_code=403,
            details=merged_details,
        )


class RateLimitExceededError(NotificationError):
    """Raised when notification volume exceeds the configured rate limit window."""

    def __init__(
        self,
        tenant_id: str,
        limit: int,
        details: dict[str, Any] | None = None,
    ) -> None:
        merged_details = details or {}
        merged_details["tenant_id"] = tenant_id
        merged_details["limit"] = limit
        super().__init__(
            message=f"Notification rate limit of {limit} msgs/min exceeded for tenant '{tenant_id}'.",
            error_code="ERR_NOTIFICATION_RATE_LIMIT",
            status_code=429,
            details=merged_details,
        )


class PayloadSanitizationError(NotificationError):
    """Raised when payload sanitization fails."""

    def __init__(
        self,
        message: str = "Failed to sanitize notification payload.",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            message=message,
            error_code="ERR_PAYLOAD_SANITIZATION_FAILED",
            status_code=400,
            details=details or {},
        )
