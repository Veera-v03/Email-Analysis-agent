"""Orchestrator and helper builders implementing the planner module behavior."""

from __future__ import annotations

import time
from datetime import UTC, datetime
from typing import Any

from src.analyzers.agent.registry import IToolRegistry
from src.models.agent import AgentState
from src.planner.exceptions.planner_exceptions import JSONValidationError
from src.planner.interfaces.planner import (
    ExecutionPlanBuilder,
    LLMProvider,
    Planner,
    PlannerContextBuilder,
    PlanningPolicy,
    PromptProvider,
)
from src.planner.models.planner import (
    ExecutionPlan,
    PlannerContext,
    PlannerMetadata,
    PlannerUsage,
    PlanningOptions,
    PlanningResult,
    ToolSelection,
)
from src.utils.logging import get_logger

logger = get_logger(__name__)


class DefaultPlannerContextBuilder(PlannerContextBuilder):
    """Default implementation for converting AgentState into LLM-consumable PlannerContext."""

    def __init__(
        self,
        registry: IToolRegistry,
        memory_retrieval: Any | None = None,
    ) -> None:
        self._registry = registry
        self._memory_retrieval = memory_retrieval

    def build_context(self, state: AgentState) -> PlannerContext:
        """Construct a PlannerContext representation of the current agent state."""
        available_tools = []
        for metadata in self._registry.list_metadata():
            available_tools.append(
                ToolSelection(
                    name=metadata.name,
                    description=metadata.description,
                    capabilities=tuple(c.value for c in metadata.capabilities),
                )
            )

        history = []
        for record in state.execution_history:
            history.append(
                {
                    "step_number": record.step_number,
                    "tool_name": record.tool_name,
                    "status": record.status.value,
                    "timestamp": record.timestamp,
                    "execution_time_ms": record.execution_time_ms,
                    "details": record.details,
                }
            )

        evidence = []
        for ev in state.evidence.items:
            evidence.append(
                {
                    "category": ev.category,
                    "title": ev.title,
                    "description": ev.description,
                    "severity": ev.severity.value,
                    "source": ev.source,
                    "confidence": ev.confidence,
                }
            )

        # Truncate content body to keep prompt length size within limits
        body_summary = None
        if state.parsed_email:
            body = state.parsed_email.body_text or ""
            body_summary = body[:2000]

        return PlannerContext(
            email_id=state.parsed_email.header.message_id
            if state.parsed_email
            else None,
            email_subject=state.parsed_email.header.subject
            if state.parsed_email
            else None,
            email_sender=state.parsed_email.header.sender
            if state.parsed_email
            else None,
            email_body_summary=body_summary,
            available_tools=tuple(available_tools),
            execution_history=tuple(history),
            accumulated_evidence=tuple(evidence),
        )


class DefaultExecutionPlanBuilder(ExecutionPlanBuilder):
    """Default implementation for validating and deserializing LLM content to ExecutionPlan."""

    def build_plan(self, response_data: str | dict[str, Any]) -> ExecutionPlan:
        """Construct a strongly typed ExecutionPlan from raw response text or dict data."""
        if isinstance(response_data, str):
            from src.planner.parsers.json_parser import parse_and_validate

            return parse_and_validate(response_data, ExecutionPlan)
        else:
            return ExecutionPlan.model_validate(response_data)


class DefaultPlanningPolicy(PlanningPolicy):
    """Default safety/rule policy enforcing that the planner selects only registered tools."""

    def validate_plan(self, plan: ExecutionPlan, context: PlannerContext) -> None:
        """Validate tool names references against available tools list."""
        registered_names = {t.name for t in context.available_tools}
        for step in plan.steps:
            if step.tool not in registered_names:
                raise JSONValidationError(
                    f"Execution step references unregistered tool '{step.tool}'. "
                    f"Registered tools: {sorted(list(registered_names))}"
                )


class PlannerService(Planner):
    """Orchestrates plan generation by converting agent state, generating prompts, and calling LLM."""

    def __init__(
        self,
        provider: LLMProvider,
        prompt_provider: PromptProvider,
        registry: IToolRegistry,
        context_builder: PlannerContextBuilder | None = None,
        plan_builder: ExecutionPlanBuilder | None = None,
        policy: PlanningPolicy | None = None,
        default_options: PlanningOptions | None = None,
    ) -> None:
        self.provider = provider
        self.prompt_provider = prompt_provider
        self.registry = registry
        self.context_builder = context_builder or DefaultPlannerContextBuilder(registry)
        self.plan_builder = plan_builder or DefaultExecutionPlanBuilder()
        self.policy = policy or DefaultPlanningPolicy()
        self.default_options = default_options or PlanningOptions()

    def plan(
        self,
        state: AgentState,
        options: PlanningOptions | None = None,
    ) -> PlanningResult:
        """Build context, call Groq provider, parse response, and return the validated execution plan."""
        start_ns = time.perf_counter_ns()
        opts = options or self.default_options

        try:
            # 1. Serialize AgentState into Context
            context = self.context_builder.build_context(state)

            # 2. Build system prompt formatted with available tools list
            tools_list_str = ""
            for tool in context.available_tools:
                caps = ", ".join(tool.capabilities)
                tools_list_str += (
                    f"- {tool.name}: {tool.description} (capabilities: [{caps}])\n"
                )

            system_prompt = self.prompt_provider.get_prompt(
                "system_prompt",
                available_tools=tools_list_str.strip(),
            )

            # 3. Format user planning prompt (supporting replanning if history exists)
            template_name = (
                "replanning_prompt" if context.execution_history else "planning_prompt"
            )

            history_lines = []
            for h in context.execution_history:
                history_lines.append(
                    f"  - Step {h['step_number']}: {h['tool_name']} ({h['status']})"
                )
            history_str = "\n".join(history_lines) if history_lines else "None"

            evidence_lines = []
            for ev in context.accumulated_evidence:
                evidence_lines.append(
                    f"  - [{ev['severity']}] {ev['title']} (from {ev['source']})"
                )
            evidence_str = "\n".join(evidence_lines) if evidence_lines else "None"

            prompt = self.prompt_provider.get_prompt(
                template_name,
                email_id=context.email_id or "Unknown",
                email_subject=context.email_subject or "No Subject",
                email_sender=context.email_sender or "Unknown",
                email_body_summary=context.email_body_summary
                or "No email body present.",
                execution_history=history_str,
                accumulated_evidence=evidence_str,
            )

            # 4. Invoke LLM provider
            response = self.provider.generate(
                prompt=prompt,
                system_prompt=system_prompt,
                options=opts,
            )

            # 5. Deserialize response
            plan = self.plan_builder.build_plan(response.content)

            # 6. Apply policy constraints
            self.policy.validate_plan(plan, context)

            latency_ms = max(0, int((time.perf_counter_ns() - start_ns) / 1_000_000))

            metadata = PlannerMetadata(
                provider="groq",
                model=response.metadata.get(
                    "model", getattr(self.provider, "_default_model", "openai/gpt-oss-20b")
                ),
                latency_ms=latency_ms,
                timestamp=datetime.now(UTC).isoformat(),
                additional_metadata=response.metadata,
            )

            return PlanningResult(
                plan=plan,
                metadata=metadata,
                usage=response.usage,
                success=True,
            )

        except Exception as e:
            logger.warning("PlannerService LLM provider error (%s).", e)
            latency_ms = max(0, int((time.perf_counter_ns() - start_ns) / 1_000_000))

            # If rate limit (429) or transient provider error occurs, provide deterministic fallback plan
            err_str = str(e).lower()
            if (
                "429" in err_str
                or "rate-limiting" in err_str
                or "rate limit" in err_str
                or "transient" in err_str
            ):
                fallback_plan = self._create_fallback_plan(context)
                metadata = PlannerMetadata(
                    provider="fallback_rule_engine",
                    model="deterministic-fallback-v1",
                    latency_ms=latency_ms,
                    timestamp=datetime.now(UTC).isoformat(),
                    additional_metadata={
                        "error_type": e.__class__.__name__,
                        "error_details": str(e)[:512],
                    },
                )
                return PlanningResult(
                    plan=fallback_plan,
                    metadata=metadata,
                    usage=PlannerUsage(),
                    success=True,
                )

            metadata = PlannerMetadata(
                provider="groq",
                model="unknown",
                latency_ms=latency_ms,
                timestamp=datetime.now(UTC).isoformat(),
                additional_metadata={"error_type": e.__class__.__name__},
            )
            return PlanningResult(
                plan=None,
                metadata=metadata,
                usage=PlannerUsage(),
                success=False,
                error_message=str(e)[:1024],
            )

    def _create_fallback_plan(self, context: Any = None) -> ExecutionPlan:
        """Construct a deterministic full-coverage investigation plan using registered tools."""
        from src.planner.models.planner import (
            ExecutionPlan,
            ExecutionStep,
            ExecutionStrategy,
        )

        # If tools have already executed in history, complete the investigation with zero remaining steps
        if context and context.execution_history:
            return ExecutionPlan(
                strategy=ExecutionStrategy.COMPREHENSIVE,
                goal="Deterministic investigation scan completed.",
                steps=(),
                confidence=0.95,
            )

        candidate_tools = [
            ("parser_tool", "Parse header and email payload structure."),
            ("sender_tool", "Verify sender domain authentication SPF/DKIM."),
            ("url_tool", "Inspect embedded links for typosquatting."),
            ("attachment_tool", "Inspect attachments if present."),
            ("ocr_tool", "Extract text from image attachments."),
            ("qr_tool", "Scan embedded QR code payloads."),
            ("threat_intelligence_tool", "Check threat intelligence databases."),
            ("campaign_correlation_tool", "Correlate with campaign memory."),
            ("report_tool", "Compile final explainable evidence report."),
        ]

        steps: list[ExecutionStep] = []
        priority = 1
        for tool_name, reason in candidate_tools:
            if self.registry.get(tool_name) is not None:
                steps.append(
                    ExecutionStep(
                        tool=tool_name,
                        priority=priority,
                        reason=reason,
                        step_id=f"{tool_name}_{priority}",
                    )
                )
                priority += 1

        if not steps:
            steps.append(
                ExecutionStep(
                    tool="parser_tool",
                    priority=1,
                    reason="Parse email structure.",
                    step_id="parser_tool_1",
                )
            )

        return ExecutionPlan(
            strategy=ExecutionStrategy.COMPREHENSIVE,
            goal="Comprehensive security scan via deterministic fallback rules.",
            steps=tuple(steps),
            confidence=0.85,
        )
