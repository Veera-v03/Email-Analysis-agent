"""Comprehensive unit and integration tests for Phase 6.3 - 6.10 features."""

from __future__ import annotations

from typing import Any

import pytest

from src.analyzers.agent.contracts import AgentTool
from src.analyzers.agent.registry import ToolRegistry
from src.models.agent import (
    AgentState,
    ToolCapability,
    ToolErrorInfo,
    ToolEvidence,
    ToolExecutionStatus,
    ToolMetadata,
    ToolResult,
)
from src.models.email import EmailHeader, EmailInput
from src.models.evidence import Evidence, EvidenceSeverity
from src.planner import (
    ConfigurablePlanningPolicy,
    ExecutionPlan,
    ExecutionStep,
    ExecutionStrategy,
    ExplainabilityEngine,
    MultiStepInvestigator,
    Planner,
    PlannerContext,
    PlannerEvaluator,
    PlannerOrchestrator,
    PlannerService,
    PlannerUsage,
    PlanningOptions,
    PlanningPolicyConfig,
    PlanningResult,
    ProviderResponse,
    ReasoningEngine,
    StepExecutionStatus,
)
from src.planner.exceptions.planner_exceptions import JSONValidationError
from src.planner.interfaces.planner import LLMProvider, PromptProvider
from src.planner.models.planner import PlannerMetadata


def PlannerMetadata_Mock() -> PlannerMetadata:
    return PlannerMetadata(
        provider="mock",
        model="mock-model",
        latency_ms=10,
        timestamp="2026-07-28T12:00:00Z",
    )


# --- Dummy/Mock Tools for Testing ---


class TestSenderTool(AgentTool[AgentState]):
    def __init__(self) -> None:
        super().__init__(
            ToolMetadata(
                name="sender_tool",
                description="Checks sender integrity.",
                version="1.0.0",
                capabilities=(ToolCapability.SENDER,),
            )
        )

    def execute(self, input_data: AgentState) -> ToolResult:
        evidence = ToolEvidence(
            category="sender_verification",
            detail="Sender verification passed.",
            metadata={"severity": "info", "confidence": 0.95},
        )
        return ToolResult(
            tool_name=self.metadata.name,
            status=ToolExecutionStatus.COMPLETED,
            evidence=(evidence,),
        )


class TestURLTool(AgentTool[AgentState]):
    def __init__(self) -> None:
        super().__init__(
            ToolMetadata(
                name="url_tool",
                description="Scans URLs.",
                version="1.0.0",
                capabilities=(ToolCapability.URL,),
            )
        )

    def execute(self, input_data: AgentState) -> ToolResult:
        evidence = ToolEvidence(
            category="url_reputation",
            detail="Suspicious URL detected: https://phishing.com/login",
            metadata={"severity": "high", "confidence": 0.85},
        )
        return ToolResult(
            tool_name=self.metadata.name,
            status=ToolExecutionStatus.COMPLETED,
            evidence=(evidence,),
            metadata={"total_urls_extracted": 1},
        )


class TestAttachmentTool(AgentTool[AgentState]):
    def __init__(self) -> None:
        super().__init__(
            ToolMetadata(
                name="attachment_tool",
                description="Analyzes attachments.",
                version="1.0.0",
                capabilities=(ToolCapability.ATTACHMENT,),
            )
        )

    def execute(self, input_data: AgentState) -> ToolResult:
        evidence = ToolEvidence(
            category="attachment_analysis",
            detail="Malware signature matched in zip archive.",
            metadata={"severity": "critical", "confidence": 0.99},
        )
        return ToolResult(
            tool_name=self.metadata.name,
            status=ToolExecutionStatus.COMPLETED,
            evidence=(evidence,),
        )


class TestFailingRetryTool(AgentTool[AgentState]):
    def __init__(self) -> None:
        super().__init__(
            ToolMetadata(
                name="failing_retry_tool",
                description="Fails once, then succeeds.",
                version="1.0.0",
            )
        )
        self.attempts = 0

    def execute(self, input_data: AgentState) -> ToolResult:
        self.attempts += 1
        if self.attempts < 2:
            return ToolResult(
                tool_name=self.metadata.name,
                status=ToolExecutionStatus.FAILED,
                error=ToolErrorInfo(
                    code="transient_err", message="Transient error occurred."
                ),
            )
        return ToolResult(
            tool_name=self.metadata.name,
            status=ToolExecutionStatus.COMPLETED,
            evidence=(
                ToolEvidence(
                    category="retry_success",
                    detail="Succeeded after retry.",
                    metadata={"severity": "info"},
                ),
            ),
        )


# --- 1. Policy Validation Tests ---


def test_configurable_planning_policy_basic() -> None:
    registry = ToolRegistry()
    registry.register(TestSenderTool())
    registry.register(TestURLTool())

    context = PlannerContextBuilder_Mock(registry)

    # Valid plan
    plan = ExecutionPlan(
        goal="Test plan validation",
        strategy=ExecutionStrategy.BALANCED,
        steps=(
            ExecutionStep(tool="sender_tool", priority=1, reason="Check sender"),
            ExecutionStep(tool="url_tool", priority=2, reason="Scan urls"),
        ),
        confidence=0.9,
    )

    policy = ConfigurablePlanningPolicy()
    # Should validate successfully
    policy.validate_plan(plan, context)


def test_policy_invalid_tool() -> None:
    registry = ToolRegistry()
    registry.register(TestSenderTool())
    context = PlannerContextBuilder_Mock(registry)

    plan = ExecutionPlan(
        goal="Plan with unknown tool",
        strategy=ExecutionStrategy.MINIMAL,
        steps=(
            ExecutionStep(tool="unknown_tool", priority=1, reason="Unavailable tool"),
        ),
        confidence=0.9,
    )

    policy = ConfigurablePlanningPolicy()
    with pytest.raises(JSONValidationError, match="references unregistered tool"):
        policy.validate_plan(plan, context)


def test_policy_circular_dependency() -> None:
    registry = ToolRegistry()
    registry.register(TestSenderTool())
    registry.register(TestURLTool())
    context = PlannerContextBuilder_Mock(registry)

    plan = ExecutionPlan(
        goal="Circular dependency test",
        strategy=ExecutionStrategy.BALANCED,
        steps=(
            ExecutionStep(
                step_id="step_1",
                tool="sender_tool",
                priority=1,
                reason="Reason",
                dependencies=("step_2",),
            ),
            ExecutionStep(
                step_id="step_2",
                tool="url_tool",
                priority=2,
                reason="Reason",
                dependencies=("step_1",),
            ),
        ),
        confidence=0.9,
    )

    policy = ConfigurablePlanningPolicy()
    with pytest.raises(JSONValidationError, match="Circular dependency detected"):
        policy.validate_plan(plan, context)


def test_policy_cost_and_confidence_thresholds() -> None:
    registry = ToolRegistry()
    registry.register(TestSenderTool())
    context = PlannerContextBuilder_Mock(registry)

    policy = ConfigurablePlanningPolicy(
        PlanningPolicyConfig(confidence_threshold=0.8, cost_limit=1.0)
    )

    # Low confidence should fail
    plan_low_conf = ExecutionPlan(
        goal="Goal",
        strategy=ExecutionStrategy.MINIMAL,
        steps=(ExecutionStep(tool="sender_tool", priority=1, reason="Check"),),
        confidence=0.7,
    )
    with pytest.raises(JSONValidationError, match="confidence"):
        policy.validate_plan(plan_low_conf, context)

    # High cost should fail
    plan_high_cost = ExecutionPlan(
        goal="Goal",
        strategy=ExecutionStrategy.MINIMAL,
        steps=(
            ExecutionStep(
                tool="sender_tool", priority=1, reason="Check", estimated_cost=1.5
            ),
        ),
        confidence=0.9,
    )
    with pytest.raises(JSONValidationError, match="cost"):
        policy.validate_plan(plan_high_cost, context)


# --- 2. Orchestration Tests ---


def test_orchestrator_dependency_sorting() -> None:
    registry = ToolRegistry()
    sender_tool = TestSenderTool()
    url_tool = TestURLTool()
    registry.register(sender_tool)
    registry.register(url_tool)

    orchestrator = PlannerOrchestrator(registry)
    state = AgentState.create()

    # Plan where dependencies are specified in non-sorted order
    plan = ExecutionPlan(
        goal="Dependencies sort check",
        strategy=ExecutionStrategy.BALANCED,
        steps=(
            ExecutionStep(
                step_id="scan_urls",
                tool="url_tool",
                priority=2,
                reason="URLs",
                dependencies=("check_sender",),
            ),
            ExecutionStep(
                step_id="check_sender", tool="sender_tool", priority=1, reason="Sender"
            ),
        ),
        confidence=0.9,
    )

    res = orchestrator.execute_plan(state, plan)
    assert res.success is True
    # The tool execution logs (records) order should be: sender_tool then url_tool
    assert res.summary.records[0].tool_name == "sender_tool"
    assert res.summary.records[1].tool_name == "url_tool"


def test_orchestrator_conditional_skip() -> None:
    registry = ToolRegistry()
    registry.register(TestURLTool())

    orchestrator = PlannerOrchestrator(registry)

    # State with no URLs in body text
    state_no_urls = AgentState.create(
        parsed_email=EmailInput(
            header=EmailHeader(
                message_id="<id>",
                sender="sender@test.com",
                recipients=["recipient@test.com"],
                subject="Sub",
                sent_at="2026-07-28",
            ),
            body_text="No links here at all.",
            attachments=[],
        )
    )

    plan = ExecutionPlan(
        goal="Conditional scan",
        strategy=ExecutionStrategy.BALANCED,
        steps=(
            ExecutionStep(
                step_id="scan_urls",
                tool="url_tool",
                priority=1,
                reason="Check",
                conditions=("has_urls",),
            ),
        ),
        confidence=0.9,
    )

    res = orchestrator.execute_plan(state_no_urls, plan)
    assert res.summary.skipped_steps == 1
    assert res.summary.records[0].status == StepExecutionStatus.SKIPPED


def test_orchestrator_retries() -> None:
    registry = ToolRegistry()
    retry_tool = TestFailingRetryTool()
    registry.register(retry_tool)

    orchestrator = PlannerOrchestrator(registry)
    state = AgentState.create()

    plan = ExecutionPlan(
        goal="Retry run",
        strategy=ExecutionStrategy.MINIMAL,
        steps=(
            ExecutionStep(
                tool="failing_retry_tool",
                priority=1,
                reason="Check",
                retry_policy={"max_retries": 2, "delay": 0.01},
            ),
        ),
        confidence=0.9,
    )

    res = orchestrator.execute_plan(state, plan)
    assert res.success is True
    assert res.summary.completed_steps == 1
    assert res.summary.records[0].retry_count == 1


# --- 3. Multi-Step Investigation Tests ---


class MockPlanner(Planner):
    def __init__(self, plans: list[ExecutionPlan]) -> None:
        self.plans = plans
        self.call_count = 0

    def plan(
        self, state: AgentState, options: PlanningOptions | None = None
    ) -> PlanningResult:
        if self.call_count >= len(self.plans):
            # Return empty plan to stop loop
            empty_plan = ExecutionPlan(
                goal="Finish",
                strategy=ExecutionStrategy.MINIMAL,
                steps=(),
                confidence=1.0,
            )
            return PlanningResult(
                plan=empty_plan,
                metadata=PlannerMetadata_Mock(),
                usage=PlannerUsage(),
                success=True,
            )

        plan = self.plans[self.call_count]
        self.call_count += 1
        return PlanningResult(
            plan=plan,
            metadata=PlannerMetadata_Mock(),
            usage=PlannerUsage(),
            success=True,
        )


def test_multi_step_investigator_loop() -> None:
    registry = ToolRegistry()
    registry.register(TestSenderTool())
    registry.register(TestURLTool())

    # Step 1: Run sender tool
    plan1 = ExecutionPlan(
        goal="Verify sender",
        strategy=ExecutionStrategy.BALANCED,
        steps=(
            ExecutionStep(
                step_id="check_sender",
                tool="sender_tool",
                priority=1,
                reason="Check sender",
            ),
        ),
        confidence=0.9,
    )
    # Step 2: Run URL tool based on sender details
    plan2 = ExecutionPlan(
        goal="Verify URLs",
        strategy=ExecutionStrategy.BALANCED,
        steps=(
            ExecutionStep(
                step_id="scan_urls", tool="url_tool", priority=1, reason="Scan urls"
            ),
        ),
        confidence=0.95,
    )

    planner = MockPlanner([plan1, plan2])
    orchestrator = PlannerOrchestrator(registry)
    investigator = MultiStepInvestigator(planner, orchestrator)

    state = AgentState.create()
    res = investigator.investigate(state)

    assert res.success is True
    assert res.iterations == 2
    assert (
        len(res.state.planning_decisions) == 3
    )  # Decision 1, Decision 2, Decision Final
    assert res.state.planning_decisions[-1].is_final is True


# --- 4. Reasoning Engine Tests ---


def test_reasoning_engine_critical_threat() -> None:
    engine = ReasoningEngine()

    # Build state with SPF fail, malicious URL, and critical malware signature match evidence
    state = AgentState.create()
    ev1 = Evidence(
        category="sender_authentication",
        title="SPF Fail",
        description="SPF verification failed for sender.",
        severity=EvidenceSeverity.HIGH,
        source="sender_tool",
        confidence=0.95,
    )
    ev2 = Evidence(
        category="url_reputation",
        title="Malicious URL",
        description="Blacklisted URL matching phishing landing page.",
        severity=EvidenceSeverity.HIGH,
        source="url_tool",
        confidence=0.9,
    )
    ev3 = Evidence(
        category="attachment_analysis",
        title="Malware Signature",
        description="ZIP file contains malicious executable payload.",
        severity=EvidenceSeverity.CRITICAL,
        source="attachment_tool",
        confidence=0.99,
    )

    state = state.model_copy(update={"evidence": state.evidence.add((ev1, ev2, ev3))})
    verdict = engine.reason(state)

    assert verdict.risk_level == "critical"
    assert "Block email delivery" in verdict.recommended_action
    assert len(verdict.evidence_correlation) == 4


def test_reasoning_engine_safe_email() -> None:
    engine = ReasoningEngine()
    state = AgentState.create()

    verdict = engine.reason(state)
    assert verdict.risk_level == "low"
    assert "Deliver normally" in verdict.recommended_action


# --- 5. Explainability & Final Report Tests ---


def test_explainability_report_compilation() -> None:
    explain_engine = ExplainabilityEngine()
    reasoning_engine = ReasoningEngine()

    state = AgentState.create()
    # Add a mock execution record
    state = state.with_tool_result(
        ToolResult(
            tool_name="sender_tool",
            status=ToolExecutionStatus.COMPLETED,
            evidence=(),
            execution_time_ms=120,
        )
    )

    verdict = reasoning_engine.reason(state)
    report = explain_engine.generate_report(state, verdict)

    assert report.risk_level == "low"
    assert "sender_tool" in report.executed_tools
    assert report.execution_statistics["tool_execution_count"] == 1
    assert report.execution_statistics["total_investigation_time_ms"] == 120


# --- 6. Evaluator Framework Tests ---


class MockScenarioLLMProvider(LLMProvider):
    """Mock LLM response tailored to evaluate scenarios."""

    def generate(
        self,
        prompt: str,
        system_prompt: str | None = None,
        options: PlanningOptions | None = None,
    ) -> ProviderResponse:
        # Generate dynamic plan depending on prompt context
        prompt_lower = prompt.lower()
        if "invoice" in prompt_lower or "outstanding" in prompt_lower:
            strategy = "comprehensive"
            steps = [
                {"tool": "sender_tool", "priority": 1, "reason": "Check"},
                {"tool": "url_tool", "priority": 2, "reason": "Check"},
            ]
        elif "newsletter" in prompt_lower or "digest" in prompt_lower:
            strategy = "minimal"
            steps = [
                {"tool": "sender_tool", "priority": 1, "reason": "Check"},
            ]
        else:
            strategy = "balanced"
            steps = [
                {"tool": "sender_tool", "priority": 1, "reason": "Check"},
            ]

        content = f"""
        {{
          "goal": "Verify email safety",
          "strategy": "{strategy}",
          "steps": {str(steps).replace("'", '"')},
          "confidence": 0.95
        }}
        """
        return ProviderResponse(
            content=content, usage=PlannerUsage(), metadata={"model": "mock-model"}
        )


def test_evaluator_runs_scenarios() -> None:
    registry = ToolRegistry()
    registry.register(TestSenderTool())
    registry.register(TestURLTool())

    mock_llm = MockScenarioLLMProvider()

    class DynamicPromptProvider(PromptProvider):
        def get_prompt(self, template_name: str, **kwargs: Any) -> str:
            # Pass sender, subject, and body to allow MockScenarioLLMProvider to match
            return f"Sender: {kwargs.get('email_sender', '')} Subject: {kwargs.get('email_subject', '')} Body: {kwargs.get('email_body_summary', '')}"

    prompter = DynamicPromptProvider()

    planner = PlannerService(
        provider=mock_llm, prompt_provider=prompter, registry=registry
    )
    evaluator = PlannerEvaluator(planner)

    # Test evaluating Newsletter and Invoice Scam
    from src.planner.evaluation.dataset import SCENARIOS

    scenarios_to_test = [
        s for s in SCENARIOS if s.name in ("Newsletter", "Invoice Scam")
    ]

    report = evaluator.evaluate_all(scenarios_to_test)
    assert report.total_scenarios == 2
    assert report.success_rate == 100.0
    assert report.strategy_accuracy == 100.0
    assert report.average_tool_f1 > 0.8


# --- Helper Mocks ---


def PlannerContextBuilder_Mock(registry: ToolRegistry) -> PlannerContext:
    from src.planner.services.planner_service import DefaultPlannerContextBuilder

    builder = DefaultPlannerContextBuilder(registry)
    return builder.build_context(AgentState.create())
