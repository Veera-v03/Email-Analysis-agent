"""Multi-step investigation engine executing iterative planning-action-evidence loops."""

from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt

from src.models.agent import AgentState, PlanningDecision
from src.planner.interfaces.planner import Planner
from src.planner.models.planner import ExecutionPlan, PlanningResult
from src.planner.orchestration import OrchestrationSummary, PlannerOrchestrator


class InvestigationResult(BaseModel):
    """Result of a complete multi-step investigation loop."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    state: AgentState
    iterations: StrictInt = Field(ge=0)
    history: tuple[OrchestrationSummary, ...] = Field(default_factory=tuple)
    success: StrictBool
    message: str = ""


class MultiStepInvestigator:
    """Manages iterative investigations by loop-feeding planner and orchestrator."""

    def __init__(
        self,
        planner: Planner,
        orchestrator: PlannerOrchestrator,
        max_iterations: int = 5,
    ) -> None:
        self.planner = planner
        self.orchestrator = orchestrator
        self.max_iterations = max_iterations

    def investigate(
        self,
        state: AgentState,
        cancel_requested: Callable[[], bool] | None = None,
    ) -> InvestigationResult:
        """Run iterative planning, execution, and replanning loop until done or limit reached."""
        current_state = state
        iteration = 0
        history: list[OrchestrationSummary] = []
        executed_step_ids: set[str] = set()

        while iteration < self.max_iterations:
            if cancel_requested and cancel_requested():
                return InvestigationResult(
                    state=current_state,
                    iterations=iteration,
                    history=tuple(history),
                    success=False,
                    message="Investigation cancelled by caller.",
                )

            # 1. Generate plan using current agent state
            plan_res: PlanningResult = self.planner.plan(current_state)

            if not plan_res.success or not plan_res.plan:
                # Planner failed or validation rejected plan
                err_msg = plan_res.error_message or "Planner returned invalid plan."
                return InvestigationResult(
                    state=current_state,
                    iterations=iteration,
                    history=tuple(history),
                    success=False,
                    message=f"Investigation failed during planning step: {err_msg}",
                )

            plan: ExecutionPlan = plan_res.plan

            # 2. Check if plan is empty or contains only already executed/seen steps
            new_steps = [s for s in plan.steps if s.step_id not in executed_step_ids]

            if not new_steps:
                # No new steps proposed by the planner - investigation completed successfully!
                # Record final planning decision
                final_decision = PlanningDecision(
                    decision_id=f"decision_{uuid.uuid4().hex[:12]}",
                    reasoning=f"Investigation completed: no more steps requested. Planner goal: {plan.goal}",
                    confidence=plan.confidence,
                    is_final=True,
                    timestamp=datetime.now(UTC).isoformat(),
                    metadata={
                        "iterations": iteration,
                        "goal": plan.goal,
                        "strategy": plan.strategy.value,
                    },
                )
                current_state = current_state.with_planning_decision(final_decision)
                break

            # Record planning decision for this step
            decision = PlanningDecision(
                decision_id=f"decision_{uuid.uuid4().hex[:12]}",
                reasoning=f"Iterative plan for step {iteration + 1}: {plan.goal}",
                confidence=plan.confidence,
                is_final=False,
                timestamp=datetime.now(UTC).isoformat(),
                metadata={
                    "proposed_steps": [s.step_id for s in plan.steps],
                    "proposed_tools": [s.tool for s in plan.steps],
                    "step_tool_map": {s.step_id: s.tool for s in plan.steps},
                    "new_steps": [s.step_id for s in new_steps],
                    "goal": plan.goal,
                    "strategy": plan.strategy.value,
                },
            )
            current_state = current_state.with_planning_decision(decision)

            # 3. Execute plan via Orchestrator
            orch_res = self.orchestrator.execute_plan(
                current_state, plan, cancel_requested=cancel_requested
            )

            # Record execution summary
            history.append(orch_res.summary)
            current_state = orch_res.state

            # Record executed step_ids to prevent infinite loops
            for record in orch_res.summary.records:
                if record.status in (
                    StepExecutionStatus.COMPLETED,
                    StepExecutionStatus.FAILED,
                    StepExecutionStatus.SKIPPED,
                ):
                    executed_step_ids.add(record.step_id)

            iteration += 1

            # If execution completely failed (e.g. key tool failed), or cancelled, we check whether to continue
            # If orchestrator execution was not successful, but continue_on_failure is enabled in execution record, we can continue.
            # In multi-step mode, we check if the plan has any completed tool or we try replanning.
            # If 0 tools were completed, and we had failures/cancels, break to avoid looping failures.
            if (
                orch_res.summary.completed_steps == 0
                and orch_res.summary.failed_steps > 0
            ):
                return InvestigationResult(
                    state=current_state,
                    iterations=iteration,
                    history=tuple(history),
                    success=False,
                    message="Investigation halted: plan execution returned zero completed steps and recorded failures.",
                )

        success = iteration < self.max_iterations or (
            iteration == self.max_iterations and len(new_steps) == 0
        )
        msg = (
            "Investigation completed successfully."
            if success
            else "Halted: reached iteration limit."
        )

        return InvestigationResult(
            state=current_state,
            iterations=iteration,
            history=tuple(history),
            success=success,
            message=msg,
        )


# Import StepExecutionStatus locally to avoid circular dependency
from src.planner.orchestration import StepExecutionStatus
