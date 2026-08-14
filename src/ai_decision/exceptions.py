"""AI Decision Planner Module exception hierarchy for ScamON Enterprise."""

from __future__ import annotations

from typing import Any

from src.common.exceptions import ScamONError


class AIDecisionError(ScamONError):
    """Base exception for all AI Decision Planner & Explainability Engine errors."""

    def __init__(
        self,
        message: str,
        error_code: str = "ERR_AI_DECISION_FAILED",
        status_code: int = 500,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            message=message,
            error_code=error_code,
            status_code=status_code,
            details=details,
        )


class LLMProviderError(AIDecisionError):
    """Raised when an LLM provider invocation or REST connection fails."""

    def __init__(
        self,
        provider_name: str,
        message: str = "LLM provider invocation failed",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            message=f"[{provider_name}] {message}",
            error_code="ERR_LLM_PROVIDER_FAILED",
            status_code=502,
            details=details,
        )


class GuardrailViolationError(AIDecisionError):
    """Raised when AI completion output fails AI Guardrail verification checks."""

    def __init__(
        self,
        violation_reason: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            message=f"AI Guardrail Violation: {violation_reason}",
            error_code="ERR_AI_GUARDRAIL_VIOLATION",
            status_code=422,
            details=details,
        )


class DecisionValidationError(AIDecisionError):
    """Raised when LLM output fails Pydantic DecisionPlan JSON schema validation."""

    def __init__(
        self,
        message: str = "Decision Plan JSON schema validation failed",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            message=message,
            error_code="ERR_DECISION_VALIDATION_FAILED",
            status_code=422,
            details=details,
        )
