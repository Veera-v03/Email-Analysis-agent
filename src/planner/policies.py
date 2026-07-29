"""Configurable planning policies for validating investigation plans."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from src.planner.exceptions.planner_exceptions import JSONValidationError
from src.planner.interfaces.planner import PlanningPolicy
from src.planner.models.planner import ExecutionPlan, PlannerContext


class PlanningPolicyConfig(BaseModel):
    """Configuration parameters for the planning policy rules."""

    confidence_threshold: float = Field(default=0.5, ge=0.0, le=1.0)
    max_steps: int = Field(default=10, ge=1)
    cost_limit: float = Field(default=5.0, ge=0.0)
    risk_limit: str = Field(default="high")  # low, medium, high, critical
    allow_duplicates: bool = Field(default=False)

    # Tool-specific constraints
    eligible_tools: set[str] | None = Field(
        default=None
    )  # If set, only these tools can be selected
    required_dependencies: dict[str, list[str]] = Field(
        default_factory=dict
    )  # tool_name -> list of dependency tools
    tool_priority_ranges: dict[str, tuple[int, int]] = Field(
        default_factory=dict
    )  # tool_name -> (min_prio, max_prio)
    preconditions: dict[str, list[str]] = Field(
        default_factory=dict
    )  # tool_name -> list of tools that must run before it


class ConfigurablePlanningPolicy(PlanningPolicy):
    """Enforces configurable domain, cost, structural, and safety constraints on plans."""

    def __init__(self, config: PlanningPolicyConfig | None = None) -> None:
        self.config = config or PlanningPolicyConfig()

    def validate_plan(self, plan: ExecutionPlan, context: PlannerContext) -> None:
        """Validate the execution plan against the current context and policy config."""
        if plan.confidence < self.config.confidence_threshold:
            raise JSONValidationError(
                f"Plan confidence ({plan.confidence:.2f}) is below the minimum threshold ({self.config.confidence_threshold:.2f})."
            )

        if len(plan.steps) > self.config.max_steps:
            raise JSONValidationError(
                f"Plan steps count ({len(plan.steps)}) exceeds maximum allowed steps ({self.config.max_steps})."
            )

        # 1. Gather all registered and executed tools
        registered_tools = {t.name for t in context.available_tools}
        executed_tools = {
            h.get("tool_name")
            for h in context.execution_history
            if h.get("status") == "completed"
        }

        # 2. Structural & Tool validations
        seen_tools: set[str] = set()
        step_map: dict[str, Any] = {}
        total_cost = 0.0

        for step in plan.steps:
            # Validate unknown tool
            if step.tool not in registered_tools:
                raise JSONValidationError(
                    f"Execution step references unregistered tool '{step.tool}'. "
                    f"Registered tools: {sorted(list(registered_tools))}"
                )

            # Validate eligibility
            if (
                self.config.eligible_tools is not None
                and step.tool not in self.config.eligible_tools
            ):
                raise JSONValidationError(
                    f"Tool '{step.tool}' is not eligible under the current policy."
                )

            # Validate duplicate tool
            if not self.config.allow_duplicates and step.tool in seen_tools:
                raise JSONValidationError(
                    f"Duplicate tool invocation detected for '{step.tool}' which is disallowed by policy."
                )
            seen_tools.add(step.tool)

            # Validate step priority range
            if step.tool in self.config.tool_priority_ranges:
                min_p, max_p = self.config.tool_priority_ranges[step.tool]
                if not (min_p <= step.priority <= max_p):
                    raise JSONValidationError(
                        f"Priority {step.priority} for tool '{step.tool}' is out of policy range [{min_p}, {max_p}]."
                    )

            # Validate step_id uniqueness within the plan
            if step.step_id in step_map:
                raise JSONValidationError(
                    f"Duplicate step_id '{step.step_id}' detected in execution plan."
                )
            step_map[step.step_id] = step
            total_cost += step.estimated_cost

        # Validate cost limit
        if total_cost > self.config.cost_limit:
            raise JSONValidationError(
                f"Total plan estimated cost ({total_cost:.2f}) exceeds policy limit ({self.config.cost_limit:.2f})."
            )

        # 3. Preconditions & Required Dependencies validations
        for step in plan.steps:
            # Enforce policy preconditions (e.g. parser_tool must run before URLTool)
            if step.tool in self.config.preconditions:
                for req in self.config.preconditions[step.tool]:
                    # Required precondition must be in execution history OR earlier in plan
                    is_met = req in executed_tools
                    if not is_met:
                        # Check if scheduled earlier in plan
                        for other_step in plan.steps:
                            if other_step.tool == req:
                                if other_step.priority < step.priority:
                                    is_met = True
                                    break
                    if not is_met:
                        raise JSONValidationError(
                            f"Precondition failed: Tool '{req}' must be executed before '{step.tool}'."
                        )

            # Enforce policy required dependencies (configured tool dependency mapping)
            if step.tool in self.config.required_dependencies:
                for dep in self.config.required_dependencies[step.tool]:
                    # Dependency must be present in execution history or in the current plan
                    if dep not in executed_tools and dep not in seen_tools:
                        raise JSONValidationError(
                            f"Required dependency failed: '{step.tool}' requires '{dep}' to be executed."
                        )

            # Validate step-level dependencies in plan
            for dep in step.dependencies:
                # Dependency must resolve to either a step_id in current plan, a tool name in current plan, or a completed tool in history
                exists = (
                    (dep in step_map) or (dep in seen_tools) or (dep in executed_tools)
                )
                if not exists:
                    raise JSONValidationError(
                        f"Step '{step.step_id}' depends on '{dep}' which is not scheduled in the plan or completed in history."
                    )

        # 4. Circular Dependency Check
        # Build graph of step_id dependencies within the plan
        adj: dict[str, list[str]] = {s.step_id: [] for s in plan.steps}
        for step in plan.steps:
            for dep in step.dependencies:
                # Only add edges for steps present in the plan (completed dependencies in history are resolved)
                if dep in adj:
                    adj[step.step_id].append(dep)
                else:
                    # If dep is a tool name, check if any step matches that tool name
                    for other_step in plan.steps:
                        if other_step.tool == dep:
                            adj[step.step_id].append(other_step.step_id)

        # DFS detection of cycle
        visited: dict[str, int] = {
            sid: 0 for sid in adj
        }  # 0=unvisited, 1=visiting, 2=visited

        def dfs(node: str) -> bool:
            visited[node] = 1
            for neighbor in adj[node]:
                if visited[neighbor] == 1:
                    return True  # cycle found
                if visited[neighbor] == 0:
                    if dfs(neighbor):
                        return True
            visited[node] = 2
            return False

        for sid in adj:
            if visited[sid] == 0:
                if dfs(sid):
                    raise JSONValidationError(
                        f"Circular dependency detected in execution plan involving step '{sid}'."
                    )
