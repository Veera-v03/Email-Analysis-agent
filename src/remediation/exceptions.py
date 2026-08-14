"""Remediation Subsystem domain exception hierarchy for ScamON Enterprise."""

from __future__ import annotations

from typing import Any

from src.common.exceptions import ScamONError


class RemediationError(ScamONError):
    """Base exception for all Incident Response & Remediation Engine failures."""

    def __init__(
        self,
        message: str,
        error_code: str = "ERR_REMEDIATION_FAILED",
        status_code: int = 500,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            message=message,
            error_code=error_code,
            status_code=status_code,
            details=details,
        )


class PolicyViolationError(RemediationError):
    """Raised when requested action violates tenant remediation policy."""

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(
            message=message,
            error_code="ERR_REMEDIATION_POLICY_VIOLATION",
            status_code=403,
            details=details,
        )


class ApprovalRequiredError(RemediationError):
    """Raised when high-impact action requires human authorization."""

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(
            message=message,
            error_code="ERR_HUMAN_APPROVAL_REQUIRED",
            status_code=402,
            details=details,
        )
