"""Pipeline Orchestrator Module exception hierarchy for ScamON Enterprise."""

from __future__ import annotations

from typing import Any

from src.common.exceptions import ScamONError


class OrchestratorError(ScamONError):
    """Base exception for all Pipeline Orchestrator errors."""

    def __init__(
        self,
        message: str,
        error_code: str = "ERR_ORCHESTRATOR_FAILED",
        status_code: int = 500,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            message=message,
            error_code=error_code,
            status_code=status_code,
            details=details,
        )


class StageFailureError(OrchestratorError):
    """Raised when a critical pipeline stage fails."""

    def __init__(
        self,
        stage_name: str,
        message: str = "Critical stage execution failed",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            message=f"[{stage_name}] {message}",
            error_code="ERR_CRITICAL_STAGE_FAILED",
            status_code=500,
            details=details,
        )


class PipelineCancelledError(OrchestratorError):
    """Raised when pipeline execution is cancelled via cancellation token."""

    def __init__(
        self,
        message: str = "Pipeline execution was cancelled",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            message=message,
            error_code="ERR_PIPELINE_CANCELLED",
            status_code=499,
            details=details,
        )


class SLABreachError(OrchestratorError):
    """Raised when pipeline execution exceeds strict SLA thresholds."""

    def __init__(
        self,
        stage_name: str,
        elapsed_ms: float,
        sla_limit_ms: float,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            message=f"[{stage_name}] SLA Breached: {elapsed_ms:.1f}ms exceeds limit of {sla_limit_ms:.1f}ms",
            error_code="ERR_SLA_BREACHED",
            status_code=504,
            details=details,
        )
