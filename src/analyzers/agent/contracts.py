"""Abstract contracts for the reusable Phase 5 agent-tool foundation."""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from typing import TypeVar

from src.analyzers.agent.exceptions import ToolExecutionError, ToolValidationError
from src.models.agent import (
    ToolErrorInfo,
    ToolEvidence,
    ToolExecutionStatus,
    ToolMetadata,
    ToolResult,
)

TInput = TypeVar("TInput")


class AgentTool[TInput](ABC):
    """Define the common contract every future tool will implement."""

    def __init__(self, metadata: ToolMetadata | None = None) -> None:
        self._metadata = metadata or ToolMetadata(
            name=self.__class__.__name__,
            description=f"{self.__class__.__name__} tool",
            version="0.1.0",
        )

    @property
    def metadata(self) -> ToolMetadata:
        """Return the tool metadata describing its capabilities."""
        return self._metadata

    @abstractmethod
    def execute(self, input_data: TInput) -> ToolResult:
        """Execute the tool and return a structured result."""

    def execute_with_handling(self, input_data: TInput) -> ToolResult:
        """Execute with consistent error wrapping for future tools."""
        started_ns = time.perf_counter_ns()
        try:
            return self.execute(input_data)
        except (ToolValidationError, ToolExecutionError) as error:
            return self._build_failed_result(error, started_ns)
        except Exception as error:  # pragma: no cover - defensive fallback
            return self._build_failed_result(
                ToolExecutionError(
                    str(error),
                    code="tool_unexpected_error",
                    details={"exception_type": error.__class__.__name__},
                ),
                started_ns,
            )

    def _build_failed_result(
        self,
        error: ToolValidationError | ToolExecutionError,
        started_ns: int,
    ) -> ToolResult:
        elapsed_ms = max(0, int((time.perf_counter_ns() - started_ns) / 1_000_000))
        return ToolResult(
            tool_name=self.metadata.name,
            status=ToolExecutionStatus.FAILED,
            metadata={"error_code": error.code},
            evidence=(
                ToolEvidence(
                    category="tool_error",
                    detail=str(error),
                    metadata={"error_code": error.code, **error.details},
                ),
            ),
            execution_time_ms=elapsed_ms,
            error=ToolErrorInfo(
                code=error.code,
                message=str(error),
                metadata=error.details,
            ),
        )
