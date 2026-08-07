"""Transmission analysis exception hierarchy for ScamON Enterprise."""

from __future__ import annotations

from typing import Any

from src.common.exceptions import ScamONError


class TransmissionAnalysisError(ScamONError):
    """Base exception for all header and transmission analysis errors."""

    def __init__(
        self,
        message: str,
        error_code: str = "ERR_TRANSMISSION_ANALYSIS_FAILED",
        status_code: int = 500,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            message=message,
            error_code=error_code,
            status_code=status_code,
            details=details,
        )


class HopParseError(TransmissionAnalysisError):
    """Raised when transport hop reconstruction encounters unrecoverable errors."""

    def __init__(
        self,
        message: str = "Transport hop reconstruction failed",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            message=message,
            error_code="ERR_HOP_PARSE_FAILED",
            status_code=422,
            details=details,
        )


class IdentityAnalysisError(TransmissionAnalysisError):
    """Raised when sender identity evaluation encounters malformed inputs."""

    def __init__(
        self,
        message: str = "Sender identity evaluation failed",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            message=message,
            error_code="ERR_IDENTITY_ANALYSIS_FAILED",
            status_code=422,
            details=details,
        )
