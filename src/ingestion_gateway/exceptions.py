"""Domain exceptions for Enterprise Live Mailbox Ingestion Gateway Subsystem."""

from __future__ import annotations

from src.common.exceptions import ScamONError


class IngestionGatewayError(ScamONError):
    """Base exception for all Ingestion Gateway errors."""


class ProviderConnectionError(IngestionGatewayError):
    """Raised when establishing a connection to an email provider fails."""


class AuthenticationFailedError(IngestionGatewayError):
    """Raised when mailbox authentication or token refresh fails."""


class MessageRetrievalError(IngestionGatewayError):
    """Raised when fetching message data or raw MIME content fails."""


class DuplicateMessageSuppressedError(IngestionGatewayError):
    """Raised when an ingested message is rejected as an exact duplicate."""


class PayloadSizeExceededError(IngestionGatewayError):
    """Raised when raw MIME or attachment payload exceeds configured maximum size."""


class DeadLetterError(IngestionGatewayError):
    """Raised when a poison message is transferred to the dead-letter queue."""


class DaemonLifecycleError(IngestionGatewayError):
    """Raised when daemon lifecycle state transitions fail."""
