"""Exception classes for the planning foundation."""

from __future__ import annotations

from typing import Any


class PlannerError(Exception):
    """Base exception for all planning errors."""

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}


class ProviderError(PlannerError):
    """Raised when the LLM provider fails.

    Handles timeout, rate limit, invalid response, or authentication issues.
    """

    def __init__(
        self,
        message: str,
        status_code: int | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        merged_details = {"status_code": status_code}
        if details:
            merged_details.update(details)
        super().__init__(message, details=merged_details)
        self.status_code = status_code


class PromptLoadError(PlannerError):
    """Raised when prompt loading or rendering fails."""


class JSONValidationError(PlannerError):
    """Raised when JSON parsing or schema validation fails."""
