from __future__ import annotations

from src.analyzers.agent.contracts import AgentTool
from src.analyzers.agent.exceptions import ToolValidationError
from src.models.agent import (
    ToolCapability,
    ToolEvidence,
    ToolExecutionStatus,
    ToolMetadata,
    ToolResult,
)


class SampleTool(AgentTool[str]):
    def __init__(self) -> None:
        super().__init__(
            ToolMetadata(
                name="sample_tool",
                description="A minimal sample tool for foundation tests.",
                version="1.0.0",
                capabilities=(ToolCapability.CONTENT,),
            )
        )

    def execute(self, input_data: str) -> ToolResult:
        return ToolResult(
            tool_name=self.metadata.name,
            status=ToolExecutionStatus.COMPLETED,
            metadata={"input_length": len(input_data)},
            evidence=(
                ToolEvidence(
                    category="sample",
                    detail=f"handled {input_data}",
                    metadata={"length": len(input_data)},
                ),
            ),
        )


class FailingTool(AgentTool[str]):
    def __init__(self) -> None:
        super().__init__(
            ToolMetadata(
                name="failing_tool",
                description="A tool that raises a validation error.",
                version="1.0.0",
            )
        )

    def execute(self, input_data: str) -> ToolResult:
        raise ToolValidationError(
            "Input was invalid",
            code="invalid_input",
            details={"value": input_data},
        )


def test_tool_metadata_is_reusable_and_extensible() -> None:
    tool = SampleTool()

    assert tool.metadata.name == "sample_tool"
    assert tool.metadata.version == "1.0.0"
    assert ToolCapability.CONTENT in tool.metadata.capabilities
    assert tool.metadata.description.startswith("A minimal")


def test_execute_with_handling_wraps_validation_errors() -> None:
    tool = FailingTool()

    result = tool.execute_with_handling("bad-data")

    assert result.status is ToolExecutionStatus.FAILED
    assert result.error is not None
    assert result.error.code == "invalid_input"
    assert "Input was invalid" in result.error.message
    assert result.execution_time_ms >= 0


def test_execute_with_handling_records_evidence_and_time() -> None:
    tool = SampleTool()

    result = tool.execute_with_handling("hello")

    assert result.status is ToolExecutionStatus.COMPLETED
    assert result.execution_time_ms >= 0
    assert result.evidence[0].category == "sample"
    assert "handled hello" in result.evidence[0].detail
    assert result.metadata["input_length"] == 5
