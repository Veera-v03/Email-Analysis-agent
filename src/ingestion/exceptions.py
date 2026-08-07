"""Ingestion platform exception hierarchy for ScamON Enterprise."""

from __future__ import annotations

from typing import Any

from src.common.exceptions import ScamONError


class IngestionError(ScamONError):
    """Base exception for all email ingestion platform errors."""

    def __init__(
        self,
        message: str,
        error_code: str = "ERR_INGESTION_FAILED",
        status_code: int = 500,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            message=message,
            error_code=error_code,
            status_code=status_code,
            details=details,
        )


class ProviderAuthenticationError(IngestionError):
    """Raised when email provider OAuth2 authentication or token refresh fails."""

    def __init__(
        self,
        message: str = "Provider OAuth2 authentication failed",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            message=message,
            error_code="ERR_PROVIDER_AUTH_FAILED",
            status_code=401,
            details=details,
        )


class MailboxSyncError(IngestionError):
    """Raised when initial or incremental mailbox synchronization fails."""

    def __init__(
        self,
        message: str = "Mailbox sync failed",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            message=message,
            error_code="ERR_MAILBOX_SYNC_FAILED",
            status_code=500,
            details=details,
        )


class ProviderQuotaExceededError(IngestionError):
    """Raised when provider API rate limits or quota are exceeded."""

    def __init__(
        self,
        message: str = "Provider API rate limit exceeded",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            message=message,
            error_code="ERR_PROVIDER_QUOTA_EXCEEDED",
            status_code=429,
            details=details,
        )
