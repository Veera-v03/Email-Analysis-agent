"""Planner orchestrator integrating LLM-generated execution plans with the tool engine."""

from __future__ import annotations

import time
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, StrictStr

from src.analyzers.agent.exceptions import ToolNotFoundError
from src.analyzers.agent.registry import IToolRegistry
from src.models.agent import (
    AgentState,
    ToolErrorInfo,
    ToolExecutionStatus,
)
from src.planner.models.planner import ExecutionPlan, ExecutionStep


class StepExecutionStatus(StrEnum):
    """Execution status for plan steps tracked by the orchestrator."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    CANCELLED = "cancelled"
    RETRYING = "retrying"


class StepExecutionRecord(BaseModel):
    """Detailed execution logs for a single execution step in a plan run."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    step_id: StrictStr
    tool_name: StrictStr
    status: StepExecutionStatus
    started_at: StrictStr
    finished_at: StrictStr | None = None
    execution_time_ms: StrictInt = Field(default=0, ge=0)
    error_message: StrictStr | None = None
    retry_count: StrictInt = Field(default=0, ge=0)
    estimated_cost: float = 0.0
    estimated_value: float = 0.0


class OrchestrationSummary(BaseModel):
    """Summary of the complete orchestrated execution run."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    total_steps: StrictInt = Field(ge=0)
    executed_steps: StrictInt = Field(ge=0)
    completed_steps: StrictInt = Field(ge=0)
    failed_steps: StrictInt = Field(ge=0)
    skipped_steps: StrictInt = Field(ge=0)
    cancelled_steps: StrictInt = Field(ge=0)
    total_time_ms: StrictInt = Field(ge=0)
    records: tuple[StepExecutionRecord, ...] = Field(default_factory=tuple)


class OrchestrationResult(BaseModel):
    """Result containing updated agent state and orchestration summary."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    state: AgentState
    summary: OrchestrationSummary
    success: StrictBool


class PlannerOrchestrator:
    """Orchestrates plan step execution sequentially, resolving dependencies and conditions."""

    def __init__(self, registry: IToolRegistry) -> None:
        self._registry = registry
        self._condition_evaluators: dict[str, Callable[[AgentState], bool]] = {
            "has_urls": self._eval_has_urls,
            "has_attachments": self._eval_has_attachments,
            "spf_failed": self._eval_spf_failed,
            "suspicious_sender": self._eval_suspicious_sender,
            "always_true": lambda s: True,
        }

    def register_condition(
        self, name: str, evaluator: Callable[[AgentState], bool]
    ) -> None:
        """Register a custom condition evaluator."""
        self._condition_evaluators[name] = evaluator

    def execute_plan(
        self,
        state: AgentState,
        plan: ExecutionPlan,
        cancel_requested: Callable[[], bool] | None = None,
    ) -> OrchestrationResult:
        """Run execution plan steps in topological order, observing dependencies and conditions."""
        start_time_ns = time.perf_counter_ns()
        current_state = state
        records: list[StepExecutionRecord] = []

        # 1. Topological Sort of plan steps
        try:
            sorted_steps = self._topological_sort(plan.steps, current_state)
        except ValueError:
            # Plan has circular dependency - report failure immediately
            elapsed_ms = max(
                0, int((time.perf_counter_ns() - start_time_ns) / 1_000_000)
            )
            summary = OrchestrationSummary(
                total_steps=len(plan.steps),
                executed_steps=0,
                completed_steps=0,
                failed_steps=0,
                skipped_steps=0,
                cancelled_steps=0,
                total_time_ms=elapsed_ms,
            )
            return OrchestrationResult(
                state=current_state, summary=summary, success=False
            )

        # Track tool execution results by step_id
        step_status_map: dict[str, StepExecutionStatus] = {}

        for step in sorted_steps:
            now_iso = datetime.now(UTC).isoformat()

            # Check cancellation request
            if cancel_requested and cancel_requested():
                step_status_map[step.step_id] = StepExecutionStatus.CANCELLED
                records.append(
                    StepExecutionRecord(
                        step_id=step.step_id,
                        tool_name=step.tool,
                        status=StepExecutionStatus.CANCELLED,
                        started_at=now_iso,
                        finished_at=now_iso,
                        error_message="Execution cancelled by caller.",
                        estimated_cost=step.estimated_cost,
                        estimated_value=step.estimated_value,
                    )
                )
                continue

            # 2. Check dependencies status
            dep_failed = False
            dep_skipped = False
            for dep in step.dependencies:
                dep_status = step_status_map.get(dep)
                if not dep_status:
                    # check by tool name if step_id was not used
                    for other_step in sorted_steps:
                        if other_step.tool == dep:
                            dep_status = step_status_map.get(other_step.step_id)
                            break

                if dep_status in (
                    StepExecutionStatus.FAILED,
                    StepExecutionStatus.CANCELLED,
                ):
                    dep_failed = True
                elif dep_status == StepExecutionStatus.SKIPPED:
                    dep_skipped = True

            if dep_failed:
                step_status_map[step.step_id] = StepExecutionStatus.CANCELLED
                records.append(
                    StepExecutionRecord(
                        step_id=step.step_id,
                        tool_name=step.tool,
                        status=StepExecutionStatus.CANCELLED,
                        started_at=now_iso,
                        finished_at=now_iso,
                        error_message="Dependent step failed or cancelled.",
                        estimated_cost=step.estimated_cost,
                        estimated_value=step.estimated_value,
                    )
                )
                continue

            # 3. Check conditions
            conditions_met = True
            for cond in step.conditions:
                evaluator = self._condition_evaluators.get(cond)
                if evaluator:
                    if not evaluator(current_state):
                        conditions_met = False
                        break
                else:
                    # Missing evaluator defaults to False for safety
                    conditions_met = False
                    break

            if not conditions_met:
                step_status_map[step.step_id] = StepExecutionStatus.SKIPPED
                records.append(
                    StepExecutionRecord(
                        step_id=step.step_id,
                        tool_name=step.tool,
                        status=StepExecutionStatus.SKIPPED,
                        started_at=now_iso,
                        finished_at=now_iso,
                        error_message=f"Conditions not met: {step.conditions}",
                        estimated_cost=step.estimated_cost,
                        estimated_value=step.estimated_value,
                    )
                )
                continue

            # 4. Resolve and execute tool
            step_record = self._execute_step_with_retries(step, current_state)

            # Record status and update state
            step_status_map[step.step_id] = step_record.status
            records.append(step_record)

            if step_record.status == StepExecutionStatus.COMPLETED:
                # If tool completed, let's fetch the result from registry and update state
                try:
                    tool = self._registry.get(step.tool)
                    # Note: engine is used for backwards compatibility or we run the tool directly
                    tool_start_ns = time.perf_counter_ns()
                    result = tool.execute_with_handling(current_state)
                    tool_time_ms = max(
                        0, int((time.perf_counter_ns() - tool_start_ns) / 1_000_000)
                    )

                    # Update tool result details
                    result = result.model_copy(
                        update={"execution_time_ms": tool_time_ms}
                    )
                    details = {"requested_tool": step.tool, "step_id": step.step_id}
                    current_state = current_state.with_tool_result(result, details)
                except Exception as e:
                    # Fallback update in case of unexpected state propagation error
                    error_info = ToolErrorInfo(code="propagation_error", message=str(e))
                    current_state = current_state.with_error(error_info)
            elif step_record.status == StepExecutionStatus.FAILED:
                # Add failure to state error list
                error_info = ToolErrorInfo(
                    code="tool_execution_failed",
                    message=step_record.error_message or "Tool execution failed.",
                    metadata={"tool_name": step.tool, "step_id": step.step_id},
                )
                current_state = current_state.with_error(error_info)

        # 5. Compile OrchestrationSummary
        elapsed_ms = max(0, int((time.perf_counter_ns() - start_time_ns) / 1_000_000))
        total_steps = len(plan.steps)
        executed_steps = sum(
            r.status in (StepExecutionStatus.COMPLETED, StepExecutionStatus.FAILED)
            for r in records
        )
        completed_steps = sum(
            r.status == StepExecutionStatus.COMPLETED for r in records
        )
        failed_steps = sum(r.status == StepExecutionStatus.FAILED for r in records)
        skipped_steps = sum(r.status == StepExecutionStatus.SKIPPED for r in records)
        cancelled_steps = sum(
            r.status == StepExecutionStatus.CANCELLED for r in records
        )

        summary = OrchestrationSummary(
            total_steps=total_steps,
            executed_steps=executed_steps,
            completed_steps=completed_steps,
            failed_steps=failed_steps,
            skipped_steps=skipped_steps,
            cancelled_steps=cancelled_steps,
            total_time_ms=elapsed_ms,
            records=tuple(records),
        )

        success = failed_steps == 0
        return OrchestrationResult(
            state=current_state, summary=summary, success=success
        )

    def _execute_step_with_retries(
        self, step: ExecutionStep, state: AgentState
    ) -> StepExecutionRecord:
        """Execute a step's tool and apply retries according to retry policy."""
        retry_config = step.retry_policy or {}
        max_retries = retry_config.get("max_retries", 0)
        delay = retry_config.get("delay", 0.0)

        started_at = datetime.now(UTC).isoformat()
        start_ns = time.perf_counter_ns()

        # Resolve tool
        try:
            tool = self._registry.get(step.tool)
        except ToolNotFoundError:
            return StepExecutionRecord(
                step_id=step.step_id,
                tool_name=step.tool,
                status=StepExecutionStatus.FAILED,
                started_at=started_at,
                finished_at=datetime.now(UTC).isoformat(),
                execution_time_ms=0,
                error_message=f"Tool '{step.tool}' not found in registry.",
                estimated_cost=step.estimated_cost,
                estimated_value=step.estimated_value,
            )

        retry_count = 0
        last_error_msg = ""

        while True:
            try:
                # Enforce simple local timeout if set (simulated since we run in thread)
                # Run tool execution
                result = tool.execute_with_handling(state)
                elapsed_ms = max(
                    0, int((time.perf_counter_ns() - start_ns) / 1_000_000)
                )

                if result.status == ToolExecutionStatus.COMPLETED:
                    return StepExecutionRecord(
                        step_id=step.step_id,
                        tool_name=step.tool,
                        status=StepExecutionStatus.COMPLETED,
                        started_at=started_at,
                        finished_at=datetime.now(UTC).isoformat(),
                        execution_time_ms=elapsed_ms,
                        retry_count=retry_count,
                        estimated_cost=step.estimated_cost,
                        estimated_value=step.estimated_value,
                    )
                else:
                    last_error_msg = (
                        result.error.message if result.error else "Execution failed."
                    )
            except Exception as e:
                elapsed_ms = max(
                    0, int((time.perf_counter_ns() - start_ns) / 1_000_000)
                )
                last_error_msg = str(e)

            # Check if we should retry
            if retry_count < max_retries:
                retry_count += 1
                if delay > 0:
                    time.sleep(delay)
                continue
            else:
                break

        elapsed_ms = max(0, int((time.perf_counter_ns() - start_ns) / 1_000_000))
        return StepExecutionRecord(
            step_id=step.step_id,
            tool_name=step.tool,
            status=StepExecutionStatus.FAILED,
            started_at=started_at,
            finished_at=datetime.now(UTC).isoformat(),
            execution_time_ms=elapsed_ms,
            error_message=last_error_msg,
            retry_count=retry_count,
            estimated_cost=step.estimated_cost,
            estimated_value=step.estimated_value,
        )

    def _topological_sort(
        self, steps: Sequence[ExecutionStep], state: AgentState
    ) -> list[ExecutionStep]:
        """Perform topological sort on steps based on dependencies."""
        step_map = {s.step_id: s for s in steps}

        # Build mapping of tool names in current plan to step_ids
        tool_to_step_ids: dict[str, list[str]] = {}
        for s in steps:
            tool_to_step_ids.setdefault(s.tool, []).append(s.step_id)

        adj: dict[str, list[str]] = {s.step_id: [] for s in steps}
        in_degree: dict[str, int] = {s.step_id: 0 for s in steps}

        # History tools are treated as completed/resolved
        completed_tools = {
            h.tool_name
            for h in state.execution_history
            if h.status == ToolExecutionStatus.COMPLETED
        }

        for s in steps:
            for dep in s.dependencies:
                # 1. Dependency matches a step_id in current plan
                if dep in step_map:
                    adj[dep].append(s.step_id)
                    in_degree[s.step_id] += 1
                # 2. Dependency matches a tool name in current plan
                elif dep in tool_to_step_ids:
                    for target_step_id in tool_to_step_ids[dep]:
                        adj[target_step_id].append(s.step_id)
                        in_degree[s.step_id] += 1
                # 3. Dependency matches completed tool in history - skip since resolved
                elif dep in completed_tools:
                    continue
                # 4. Unresolved dependency
                else:
                    # We still sort it but treat it as unresolvable
                    pass

        # Kahn's algorithm
        queue = [sid for sid, degree in in_degree.items() if degree == 0]
        # Sort queue by priority to preserve original step intent
        queue.sort(key=lambda sid: step_map[sid].priority)

        result: list[ExecutionStep] = []

        while queue:
            node = queue.pop(0)
            result.append(step_map[node])
            for neighbor in adj[node]:
                in_degree[neighbor] -= 1
                if in_degree[neighbor] == 0:
                    queue.append(neighbor)
            # Re-sort queue to maintain priority order
            queue.sort(key=lambda sid: step_map[sid].priority)

        if len(result) < len(steps):
            raise ValueError("Plan contains circular dependency.")

        return result

    # --- Condition Evaluators ---
    def _eval_has_urls(self, state: AgentState) -> bool:
        if not state.parsed_email:
            return False
        # Extract body
        body = state.parsed_email.body_text or ""
        if "http://" in body or "https://" in body:
            return True
        # Check URLTool execution status
        url_tool_res = state.tool_results.get("url_tool")
        if url_tool_res and url_tool_res.metadata.get("total_urls_extracted", 0) > 0:
            return True
        return False

    def _eval_has_attachments(self, state: AgentState) -> bool:
        if not state.parsed_email:
            return False
        # attachments metadata
        if state.parsed_email.attachments:
            return True
        return False

    def _eval_spf_failed(self, state: AgentState) -> bool:
        for ev in state.evidence.items:
            if "spf" in ev.category.lower() or "spf" in ev.title.lower():
                if (
                    ev.severity in ("high", "critical")
                    or "fail" in ev.description.lower()
                ):
                    return True
        return False

    def _eval_suspicious_sender(self, state: AgentState) -> bool:
        # Check sender reputation/domain details
        for ev in state.evidence.items:
            if "sender" in ev.category.lower() or "domain" in ev.category.lower():
                if ev.severity in ("medium", "high", "critical"):
                    return True
        return False
