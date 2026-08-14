"""Pipeline Lifecycle Hooks supporting tracing, SLA auditing, and metrics collection."""

from __future__ import annotations

from typing import Any

from src.config.logging import get_logger
from src.orchestrator.models import PipelineContext, StageResult

logger = get_logger("scamon.orchestrator.hooks")


class PipelineLifecycleHooks:
    """Lifecycle hook observer supporting auditing, distributed tracing, and metrics."""

    def before_stage(self, stage_name: str, context: PipelineContext) -> None:
        """Invoked before executing a pipeline stage."""
        logger.debug(
            "[%s] Entering stage execution (trace_id: %s, analysis_id: %s)",
            stage_name,
            context.trace_id,
            context.analysis_id,
        )

    def after_stage(
        self, stage_name: str, result: StageResult[Any], context: PipelineContext
    ) -> None:
        """Invoked after completing a pipeline stage."""
        logger.debug(
            "[%s] Completed stage with status %s in %.2fms",
            stage_name,
            result.status.value,
            result.execution_time_ms,
        )

    def on_stage_error(
        self, stage_name: str, error: Exception, context: PipelineContext
    ) -> None:
        """Invoked when a pipeline stage encounters an error."""
        logger.warning(
            "[%s] Stage error encountered (trace_id: %s): %s",
            stage_name,
            context.trace_id,
            error,
        )
