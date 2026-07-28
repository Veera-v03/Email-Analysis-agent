"""Deterministic runtime for executing registered agent tools sequentially."""

from __future__ import annotations

import time
from collections.abc import Sequence
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, StrictStr

from src.analyzers.agent.contracts import AgentTool
from src.analyzers.agent.exceptions import ToolNotFoundError
from src.analyzers.agent.registry import IToolRegistry
from src.models.agent import (
    AgentState,
    ToolErrorInfo,
    ToolEvidence,
    ToolExecutionStatus,
    ToolResult,
)


class ExecutionOptions(BaseModel):
    """Configure deterministic execution behavior without tool-specific policy."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    continue_on_failure: StrictBool = True
    record_execution_details: StrictBool = True


class ExecutionSummary(BaseModel):
    """Summarize one ordered tool-execution run."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    requested_tool_count: StrictInt = Field(ge=0)
    executed_tool_count: StrictInt = Field(ge=0)
    completed_count: StrictInt = Field(ge=0)
    failed_count: StrictInt = Field(ge=0)
    skipped_count: StrictInt = Field(ge=0)
    evidence_count: StrictInt = Field(ge=0)
    execution_time_ms: StrictInt = Field(ge=0)
    stopped_early: StrictBool = False
    tool_order: tuple[StrictStr, ...] = Field(default_factory=tuple)


class ExecutionResult(BaseModel):
    """Return the immutable state and summary produced by one execution run."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    state: AgentState
    results: tuple[ToolResult, ...]
    summary: ExecutionSummary


ToolReference = str | AgentTool[Any]


class ToolExecutionEngine:
    """Execute registry-resolved tools in caller-provided order.

    The engine is deliberately planner-free: it neither selects tools nor
    interprets evidence.  It only resolves, invokes, records, and summarizes.
    """

    def __init__(self, registry: IToolRegistry) -> None:
        self._registry = registry

    def execute(
        self,
        state: AgentState,
        tools: Sequence[ToolReference] | None = None,
        options: ExecutionOptions | None = None,
    ) -> ExecutionResult:
        """Run tools sequentially and return the resulting immutable state."""
        started_ns = time.perf_counter_ns()
        resolved = self._resolve_tools(tools)
        execution_options = options or ExecutionOptions()
        current_state = state
        results: list[ToolResult] = []
        stopped_early = False

        for requested_name, tool in resolved:
            tool_started_ns = time.perf_counter_ns()
            if tool is None:
                result = self._missing_tool_result(requested_name)
            else:
                result = tool.execute_with_handling(current_state)
                observed_ms = max(
                    0,
                    int((time.perf_counter_ns() - tool_started_ns) / 1_000_000),
                )
                result = result.model_copy(
                    update={"execution_time_ms": max(result.execution_time_ms, observed_ms)}
                )

            details = (
                {"requested_tool": requested_name}
                if execution_options.record_execution_details
                else None
            )
            current_state = current_state.with_tool_result(result, details)
            results.append(result)
            if result.status is ToolExecutionStatus.FAILED and not execution_options.continue_on_failure:
                stopped_early = True
                break

        elapsed_ms = max(0, int((time.perf_counter_ns() - started_ns) / 1_000_000))
        summary = self._summary(
            requested_count=len(resolved),
            results=tuple(results),
            evidence_count=len(current_state.evidence.items) - len(state.evidence.items),
            elapsed_ms=elapsed_ms,
            stopped_early=stopped_early,
        )
        return ExecutionResult(state=current_state, results=tuple(results), summary=summary)

    def _resolve_tools(
        self,
        tools: Sequence[ToolReference] | None,
    ) -> list[tuple[str, AgentTool[Any] | None]]:
        references: Sequence[ToolReference] = tools if tools is not None else self._registry.list_tools()
        resolved: list[tuple[str, AgentTool[Any] | None]] = []
        for reference in references:
            if isinstance(reference, str):
                try:
                    resolved.append((reference, self._registry.get(reference)))
                except ToolNotFoundError:
                    resolved.append((reference, None))
            elif isinstance(reference, AgentTool):
                resolved.append((reference.metadata.name, reference))
            else:
                raise TypeError("Tool references must be registered names or AgentTool instances.")
        return resolved

    @staticmethod
    def _missing_tool_result(tool_name: str) -> ToolResult:
        error = ToolErrorInfo(
            code="tool_not_found_error",
            message=f"Tool with name '{tool_name}' was not found in registry.",
            metadata={"tool_name": tool_name},
        )
        return ToolResult(
            tool_name=tool_name,
            status=ToolExecutionStatus.FAILED,
            metadata={"error_code": error.code},
            evidence=(
                ToolEvidence(
                    category="tool_error",
                    detail=error.message,
                    metadata={"severity": "info", **error.metadata},
                ),
            ),
            error=error,
        )

    @staticmethod
    def _summary(
        *,
        requested_count: int,
        results: tuple[ToolResult, ...],
        evidence_count: int,
        elapsed_ms: int,
        stopped_early: bool,
    ) -> ExecutionSummary:
        return ExecutionSummary(
            requested_tool_count=requested_count,
            executed_tool_count=len(results),
            completed_count=sum(item.status is ToolExecutionStatus.COMPLETED for item in results),
            failed_count=sum(item.status is ToolExecutionStatus.FAILED for item in results),
            skipped_count=sum(item.status is ToolExecutionStatus.SKIPPED for item in results),
            evidence_count=evidence_count,
            execution_time_ms=elapsed_ms,
            stopped_early=stopped_early,
            tool_order=tuple(item.tool_name for item in results),
        )
