"""Content Intelligence Module exception hierarchy for ScamON Enterprise."""

from __future__ import annotations

from typing import Any

from src.common.exceptions import ScamONError


class ContentIntelligenceError(ScamONError):
    """Base exception for all Content & Media Intelligence errors."""

    def __init__(
        self,
        message: str,
        error_code: str = "ERR_CONTENT_INTEL_FAILED",
        status_code: int = 500,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            message=message,
            error_code=error_code,
            status_code=status_code,
            details=details,
        )


class OCRError(ContentIntelligenceError):
    """Raised when OCR extraction encounters an error."""

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(
            message=f"OCR Failure: {message}",
            error_code="ERR_OCR_FAILED",
            status_code=500,
            details=details,
        )


class QRError(ContentIntelligenceError):
    """Raised when QR decoding encounters an error."""

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(
            message=f"QR Decoding Failure: {message}",
            error_code="ERR_QR_FAILED",
            status_code=500,
            details=details,
        )
