"""Domain exceptions for Module 19 Enterprise Threat Analytics and Reporting."""

from __future__ import annotations

from typing import Any

from src.common.exceptions import ScamONError


class AnalyticsError(ScamONError):
    """Base exception for all Module 19 analytics domain failures."""

    def __init__(
        self,
        message: str = "Threat analytics evaluation failed.",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            message=message,
            error_code="ERR_ANALYTICS_FAILED",
            status_code=500,
            details=details or {},
        )


class ReportingError(AnalyticsError):
    """Exception raised when executive or compliance report generation fails."""

    def __init__(
        self,
        message: str = "Report generation failed.",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message=message, details=details or {})
