"""Integration tests for deterministic AgentTool runtime execution."""

from __future__ import annotations

from src.analyzers.agent.contracts import AgentTool
from src.analyzers.agent.engine import ExecutionOptions, ToolExecutionEngine
from src.analyzers.agent.exceptions import ToolExecutionError
from src.analyzers.agent.registry import ToolRegistry
from src.analyzers.agent.tools.parser_tool import ParserTool
from src.analyzers.agent.tools.url_tool import URLTool
from src.models.agent import (
    AgentState,
    ToolCapability,
    ToolEvidence,
    ToolExecutionStatus,
    ToolMetadata,
    ToolResult,
)


class RecordingTool(AgentTool[AgentState]):
    """Deterministic test tool that proves ordered state propagation."""

    def __init__(self, name: str, expected_history_count: int) -> None:
        super().__init__(
            ToolMetadata(
                name=name,
                description="Records a deterministic test observation.",
                version="1.0.0",
                capabilities=(ToolCapability.CONTENT,),
            )
        )
        self._expected_history_count = expected_history_count

    def execute(self, input_data: AgentState) -> ToolResult:
        assert len(input_data.execution_history) == self._expected_history_count
        return ToolResult(
            tool_name=self.metadata.name,
            status=ToolExecutionStatus.COMPLETED,
            evidence=(
                ToolEvidence(
                    category="test_observation",
                    detail=f"{self.metadata.name} completed",
                    metadata={"severity": "low"},
                ),
            ),
        )


class FailingTool(AgentTool[AgentState]):
    """Deterministic test tool that exercises engine recovery."""

    def __init__(self) -> None:
        super().__init__(
            ToolMetadata(
                name="failing_tool",
                description="Fails predictably for runtime tests.",
                version="1.0.0",
            )
        )

    def execute(self, input_data: AgentState) -> ToolResult:
        raise ToolExecutionError("Expected failure", code="expected_failure")


def test_engine_executes_registry_tools_in_requested_order() -> None:
    registry = ToolRegistry()
    first = RecordingTool("first", expected_history_count=0)
    second = RecordingTool("second", expected_history_count=1)
    registry.register(first)
    registry.register(second)

    outcome = ToolExecutionEngine(registry).execute(
        AgentState.create(),
        tools=["first", "second"],
    )

    assert outcome.summary.tool_order == ("first", "second")
    assert outcome.summary.completed_count == 2
    assert outcome.summary.failed_count == 0
    assert outcome.summary.evidence_count == 2
    assert tuple(outcome.state.tool_results) == ("first", "second")
    assert [record.tool_name for record in outcome.state.execution_history] == [
        "first",
        "second",
    ]
    assert {evidence.source for evidence in outcome.state.evidence.items} == {
        "first",
        "second",
    }


def test_engine_passes_parser_output_to_subsequent_registered_tool() -> None:
    registry = ToolRegistry()
    registry.register(ParserTool())
    registry.register(URLTool())
    raw_email = {
        "header": {
            "message_id": "<engine@example.com>",
            "sender": "sender@example.com",
            "recipients": ["recipient@example.com"],
            "subject": "Engine parser test",
            "sent_at": "2026-07-28T10:00:00Z",
        },
        "body_text": "Parser output becomes AgentState input: https://bit.ly/example.",
    }

    outcome = ToolExecutionEngine(registry).execute(
        AgentState.create(metadata={"raw_email": raw_email}),
        tools=["parser_tool", "url_tool"],
    )

    assert outcome.state.parsed_email is not None
    assert outcome.state.parsed_email.header.message_id == "<engine@example.com>"
    assert outcome.summary.tool_order == ("parser_tool", "url_tool")
    assert outcome.state.execution_history[0].tool_name == "parser_tool"
    assert outcome.state.tool_results["url_tool"].metadata["total_urls_extracted"] == 1
    assert outcome.results[0].evidence_collection.items == (
        outcome.state.evidence.items[0],
    )


def test_engine_recovers_from_failure_and_continues_by_default() -> None:
    registry = ToolRegistry()
    registry.register(FailingTool())
    registry.register(RecordingTool("after_failure", expected_history_count=1))

    outcome = ToolExecutionEngine(registry).execute(
        AgentState.create(),
        tools=["failing_tool", "after_failure"],
    )

    assert outcome.summary.failed_count == 1
    assert outcome.summary.completed_count == 1
    assert outcome.summary.stopped_early is False
    assert outcome.state.errors[0].code == "expected_failure"
    assert outcome.state.execution_history[1].tool_name == "after_failure"


def test_engine_can_stop_after_recoverable_failure_and_record_missing_tools() -> None:
    registry = ToolRegistry()
    registry.register(FailingTool())
    registry.register(RecordingTool("not_reached", expected_history_count=1))
    engine = ToolExecutionEngine(registry)

    stopped = engine.execute(
        AgentState.create(),
        tools=["failing_tool", "not_reached"],
        options=ExecutionOptions(continue_on_failure=False),
    )
    missing = engine.execute(AgentState.create(), tools=["unknown_tool"])

    assert stopped.summary.stopped_early is True
    assert stopped.summary.executed_tool_count == 1
    assert missing.summary.failed_count == 1
    assert missing.state.errors[0].code == "tool_not_found_error"
    assert missing.state.evidence.items[0].source == "unknown_tool"


def test_engine_accepts_tool_instances_without_registry_registration() -> None:
    tool = RecordingTool("embedded", expected_history_count=0)

    outcome = ToolExecutionEngine(ToolRegistry()).execute(
        AgentState.create(),
        tools=[tool],
    )

    assert outcome.summary.tool_order == ("embedded",)
    assert (
        outcome.state.tool_results["embedded"].status is ToolExecutionStatus.COMPLETED
    )
