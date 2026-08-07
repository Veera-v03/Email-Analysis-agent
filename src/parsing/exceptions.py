"""Parsing engine exception hierarchy for ScamON Enterprise."""

from __future__ import annotations

from typing import Any

from src.common.exceptions import ScamONError


class ParsingError(ScamONError):
    """Base exception for all email parsing and decomposition errors."""

    def __init__(
        self,
        message: str,
        error_code: str = "ERR_PARSING_FAILED",
        status_code: int = 422,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            message=message,
            error_code=error_code,
            status_code=status_code,
            details=details,
        )


class MalformedMimeError(ParsingError):
    """Raised when MIME structure is severely corrupted beyond partial recovery."""

    def __init__(
        self,
        message: str = "Malformed MIME structure detected",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            message=message,
            error_code="ERR_MALFORMED_MIME",
            status_code=422,
            details=details,
        )


class AttachmentExtractionError(ParsingError):
    """Raised when attachment extraction or decoding fails unexpectedly."""

    def __init__(
        self,
        message: str = "Attachment extraction failed",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            message=message,
            error_code="ERR_ATTACHMENT_EXTRACTION_FAILED",
            status_code=500,
            details=details,
        )
