"""Threat Intelligence Module exception hierarchy for ScamON Enterprise."""

from __future__ import annotations

from typing import Any

from src.common.exceptions import ScamONError


class ThreatIntelError(ScamONError):
    """Base exception for all Threat Intelligence & IOC Enrichment errors."""

    def __init__(
        self,
        message: str,
        error_code: str = "ERR_THREAT_INTEL_FAILED",
        status_code: int = 500,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            message=message,
            error_code=error_code,
            status_code=status_code,
            details=details,
        )


class ProviderLookupError(ThreatIntelError):
    """Raised when a Threat Intelligence provider lookup fails."""

    def __init__(
        self,
        provider_name: str,
        message: str = "Provider lookup failed",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            message=f"[{provider_name}] {message}",
            error_code="ERR_PROVIDER_LOOKUP_FAILED",
            status_code=502,
            details=details,
        )


class ProviderRateLimitError(ProviderLookupError):
    """Raised when a Threat Intelligence provider rate limit is exceeded."""

    def __init__(
        self,
        provider_name: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            provider_name=provider_name,
            message="Provider rate limit exceeded",
            details=details,
        )


class CircuitBreakerOpenError(ThreatIntelError):
    """Raised when a request is made to a provider whose Circuit Breaker is OPEN."""

    def __init__(
        self,
        provider_name: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            message=f"[{provider_name}] Circuit breaker is OPEN. Requests blocked.",
            error_code="ERR_CIRCUIT_BREAKER_OPEN",
            status_code=503,
            details=details,
        )
