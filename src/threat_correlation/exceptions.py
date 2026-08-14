"""Threat Correlation Module exception hierarchy for ScamON Enterprise."""

from __future__ import annotations

from typing import Any

from src.common.exceptions import ScamONError


class ThreatCorrelationError(ScamONError):
    """Base exception for all Threat Correlation & Campaign Intelligence errors."""

    def __init__(
        self,
        message: str,
        error_code: str = "ERR_THREAT_CORRELATION_FAILED",
        status_code: int = 500,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            message=message,
            error_code=error_code,
            status_code=status_code,
            details=details,
        )
