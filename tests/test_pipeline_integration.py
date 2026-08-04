"""End-to-end handoff checks for planning, execution, reasoning, and reporting."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import cast

from src.analyzers.agent.contracts import AgentTool
from src.analyzers.agent.registry import ToolRegistry
from src.models.agent import (
    AgentState,
    ToolCapability,
    ToolEvidence,
    ToolExecutionStatus,
    ToolMetadata,
    ToolResult,
)
from src.planner.explainability import ExplainabilityEngine
from src.planner.interfaces.planner import Planner
from src.planner.investigator import MultiStepInvestigator
from src.planner.models.planner import (
    ExecutionPlan,
    ExecutionStep,
    ExecutionStrategy,
    PlannerMetadata,
    PlannerUsage,
    PlanningResult,
)
from src.planner.orchestration import PlannerOrchestrator
from src.planner.reasoning import ReasoningEngine


class CountingEvidenceTool(AgentTool[AgentState]):
    """A deterministic tool used to verify execution-result handoff."""

    def __init__(self) -> None:
        super().__init__(
            ToolMetadata(
                name="counting_evidence_tool",
                description="Emits deterministic evidence for integration testing.",
                version="1.0.0",
                capabilities=(ToolCapability.CONTENT,),
            )
        )
        self.calls = 0

    def execute(self, input_data: AgentState) -> ToolResult:
        self.calls += 1
        return ToolResult(
            tool_name=self.metadata.name,
            status=ToolExecutionStatus.COMPLETED,
            evidence=(
                ToolEvidence(
                    category="url_reputation",
                    detail="Suspicious URL detected by the executed tool.",
                    metadata={"severity": "high", "confidence": 0.9},
                ),
            ),
        )


class TwoPassPlanner:
    """Return one valid execution plan and then signal investigation completion."""

    def __init__(self) -> None:
        self.calls = 0

    def plan(self, state: AgentState, options: object = None) -> PlanningResult:
        self.calls += 1
        steps: tuple[ExecutionStep, ...]
        if self.calls == 1:
            steps = (
                ExecutionStep(
                    step_id="inspect_url",
                    tool="counting_evidence_tool",
                    priority=1,
                    reason="Inspect security indicators.",
                ),
            )
        else:
            steps = ()
        return PlanningResult(
            plan=ExecutionPlan(
                goal="End-to-end handoff verification",
                strategy=ExecutionStrategy.MINIMAL,
                steps=steps,
                confidence=0.9,
            ),
            metadata=PlannerMetadata(
                provider="test",
                model="test",
                latency_ms=0,
                timestamp=datetime.now(UTC).isoformat(),
            ),
            usage=PlannerUsage(),
            success=True,
        )


def test_pipeline_executes_each_tool_once_and_preserves_evidence_in_report() -> None:
    registry = ToolRegistry()
    tool = CountingEvidenceTool()
    registry.register(tool)
    investigator = MultiStepInvestigator(
        cast(Planner, TwoPassPlanner()),
        PlannerOrchestrator(registry),
    )

    investigation = investigator.investigate(AgentState.create())
    verdict = ReasoningEngine().reason(investigation.state)
    report = ExplainabilityEngine().generate_report(investigation.state, verdict)

    assert investigation.success is True
    assert tool.calls == 1
    assert len(investigation.state.evidence.items) == 1
    assert report.executed_tools == ("counting_evidence_tool",)
    assert len(report.evidence) == 1
    assert report.evidence[0]["category"] == "url_reputation"
