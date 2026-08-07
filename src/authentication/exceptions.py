"""Authentication Verification exception hierarchy for ScamON Enterprise."""

from __future__ import annotations

from typing import Any

from src.common.exceptions import ScamONError


class AuthenticationVerificationError(ScamONError):
    """Base exception for all SPF, DKIM, DMARC, and ARC verification errors."""

    def __init__(
        self,
        message: str,
        error_code: str = "ERR_AUTH_VERIFICATION_FAILED",
        status_code: int = 500,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            message=message,
            error_code=error_code,
            status_code=status_code,
            details=details,
        )


class SpfEvaluationError(AuthenticationVerificationError):
    """Raised when SPF DNS record evaluation encounters unrecoverable errors."""

    def __init__(
        self,
        message: str = "SPF record evaluation failed",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            message=message,
            error_code="ERR_SPF_EVALUATION_FAILED",
            status_code=422,
            details=details,
        )


class DkimVerificationError(AuthenticationVerificationError):
    """Raised when DKIM cryptographic signature verification encounters errors."""

    def __init__(
        self,
        message: str = "DKIM verification failed",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            message=message,
            error_code="ERR_DKIM_VERIFICATION_FAILED",
            status_code=422,
            details=details,
        )


class DmarcEvaluationError(AuthenticationVerificationError):
    """Raised when DMARC policy or alignment evaluation encounters errors."""

    def __init__(
        self,
        message: str = "DMARC evaluation failed",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            message=message,
            error_code="ERR_DMARC_EVALUATION_FAILED",
            status_code=422,
            details=details,
        )


class ArcValidationError(AuthenticationVerificationError):
    """Raised when ARC chain validation encounters errors."""

    def __init__(
        self,
        message: str = "ARC chain validation failed",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            message=message,
            error_code="ERR_ARC_VALIDATION_FAILED",
            status_code=422,
            details=details,
        )
