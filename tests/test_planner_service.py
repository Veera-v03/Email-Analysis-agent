"""Unit tests for the PlannerService orchestrator."""

from __future__ import annotations

from unittest import mock

from src.analyzers.agent.registry import ToolRegistry
from src.analyzers.agent.tools.parser_tool import ParserTool
from src.analyzers.agent.tools.sender_tool import SenderTool
from src.models.agent import AgentState
from src.planner.interfaces.planner import LLMProvider, PromptProvider
from src.planner.models.planner import PlanningOptions, ProviderResponse
from src.planner.services.planner_service import PlannerService


class MockLLMProvider(LLMProvider):
    """Fake LLMProvider to control model returns."""

    def __init__(self, response_content: str) -> None:
        self.response_content = response_content
        self.last_prompt = None
        self.last_system_prompt = None
        self.last_options = None

    def generate(
        self,
        prompt: str,
        system_prompt: str | None = None,
        options: PlanningOptions | None = None,
    ) -> ProviderResponse:
        self.last_prompt = prompt
        self.last_system_prompt = system_prompt
        self.last_options = options
        return ProviderResponse(
            content=self.response_content,
            metadata={"model": "mock-model"},
        )


class MockPromptProvider(PromptProvider):
    """Fake PromptProvider returning predictable strings."""

    def get_prompt(self, template_name: str, **kwargs: Any) -> str:
        # Just return a formatted name and string of kwargs for assertions
        kv_pairs = [f"{k}={v}" for k, v in sorted(kwargs.items())]
        return f"[{template_name}] " + ", ".join(kv_pairs)


def test_planner_service_success() -> None:
    """Verify standard orchestrator flow with a valid LLM response."""
    registry = ToolRegistry()
    registry.register(ParserTool())
    registry.register(SenderTool())

    mock_llm_json = """
    {
      "goal": "Verify email safety",
      "strategy": "targeted",
      "steps": [
        {"tool": "parser_tool", "priority": 1, "reason": "First parse"},
        {"tool": "sender_tool", "priority": 2, "reason": "Then check sender"}
      ],
      "confidence": 0.95
    }
    """
    llm = MockLLMProvider(mock_llm_json)
    prompter = MockPromptProvider()

    service = PlannerService(provider=llm, prompt_provider=prompter, registry=registry)

    # State with email
    state = AgentState.create().with_parsed_email(
        mock.MagicMock(
            header=mock.MagicMock(
                message_id="<msg-id>",
                sender="sender@example.com",
                subject="Hello",
            ),
            body_text="Test body",
        )
    )

    result = service.plan(state)

    assert result.success is True
    assert result.error_message is None
    assert result.plan is not None
    assert result.plan.goal == "Verify email safety"
    assert len(result.plan.steps) == 2
    assert result.plan.steps[0].tool == "parser_tool"
    assert result.plan.steps[1].tool == "sender_tool"
    assert result.metadata.provider == "groq"
    assert result.metadata.model == "mock-model"
    assert result.metadata.latency_ms >= 0


def test_planner_service_policy_failure() -> None:
    """Ensure that selecting an unregistered tool raises a validation/policy error."""
    registry = ToolRegistry()
    registry.register(ParserTool())  # sender_tool NOT registered

    mock_llm_json = """
    {
      "goal": "Verify email safety",
      "strategy": "targeted",
      "steps": [
        {"tool": "parser_tool", "priority": 1, "reason": "First parse"},
        {"tool": "sender_tool", "priority": 2, "reason": "Then check sender"}
      ],
      "confidence": 0.95
    }
    """
    llm = MockLLMProvider(mock_llm_json)
    prompter = MockPromptProvider()

    service = PlannerService(provider=llm, prompt_provider=prompter, registry=registry)
    state = AgentState.create()

    result = service.plan(state)

    # Policy error caught inside PlannerService.plan, leading to success=False
    assert result.success is False
    assert "references unregistered tool 'sender_tool'" in result.error_message


def test_planner_service_invalid_json_handled() -> None:
    """Ensure that malformed JSON returned by LLM is handled gracefully."""
    registry = ToolRegistry()
    registry.register(ParserTool())

    mock_llm_bad_json = "This is not JSON at all!"
    llm = MockLLMProvider(mock_llm_bad_json)
    prompter = MockPromptProvider()

    service = PlannerService(provider=llm, prompt_provider=prompter, registry=registry)
    state = AgentState.create()

    result = service.plan(state)

    assert result.success is False
    assert "Failed to decode response as JSON" in result.error_message
