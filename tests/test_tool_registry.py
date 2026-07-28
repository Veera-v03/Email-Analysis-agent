from __future__ import annotations

import pytest

from src.analyzers.agent.contracts import AgentTool
from src.analyzers.agent.exceptions import DuplicateToolError, ToolNotFoundError
from src.analyzers.agent.registry import ToolRegistry
from src.models.agent import (
    ToolCapability,
    ToolEvidence,
    ToolExecutionStatus,
    ToolMetadata,
    ToolResult,
)


class MockUrlTool(AgentTool[str]):
    def __init__(self) -> None:
        super().__init__(
            ToolMetadata(
                name="url_tool",
                description="Scans URLs in email body",
                version="1.0.0",
                capabilities=(ToolCapability.URL,),
                tags=("url", "security"),
            )
        )

    def execute(self, input_data: str) -> ToolResult:
        return ToolResult(
            tool_name=self.metadata.name,
            status=ToolExecutionStatus.COMPLETED,
            evidence=(
                ToolEvidence(
                    category="url_scan",
                    detail=f"Scanned {input_data}",
                ),
            ),
        )


class MockSenderTool(AgentTool[str]):
    def __init__(self) -> None:
        super().__init__(
            ToolMetadata(
                name="sender_tool",
                description="Analyzes sender reputation and SPF/DKIM",
                version="1.1.0",
                capabilities=(ToolCapability.SENDER,),
                tags=("sender", "authentication"),
            )
        )

    def execute(self, input_data: str) -> ToolResult:
        return ToolResult(
            tool_name=self.metadata.name,
            status=ToolExecutionStatus.COMPLETED,
        )


def test_register_and_get_tool() -> None:
    registry = ToolRegistry()
    url_tool = MockUrlTool()

    registry.register(url_tool)

    assert registry.has_tool("url_tool")
    retrieved = registry.get("url_tool")
    assert retrieved is url_tool
    assert retrieved.metadata.name == "url_tool"


def test_duplicate_registration_raises_duplicate_tool_error() -> None:
    registry = ToolRegistry()
    tool_1 = MockUrlTool()
    tool_2 = MockUrlTool()

    registry.register(tool_1)

    with pytest.raises(DuplicateToolError) as exc_info:
        registry.register(tool_2)

    assert exc_info.value.tool_name == "url_tool"
    assert "already registered" in str(exc_info.value)


def test_register_non_tool_object_raises_type_error() -> None:
    registry = ToolRegistry()

    with pytest.raises(TypeError):
        registry.register("not_a_tool")  # type: ignore[arg-type]


def test_get_non_existent_tool_raises_tool_not_found_error() -> None:
    registry = ToolRegistry()

    with pytest.raises(ToolNotFoundError) as exc_info:
        registry.get("non_existent_tool")

    assert exc_info.value.tool_name == "non_existent_tool"


def test_unregister_tool() -> None:
    registry = ToolRegistry()
    sender_tool = MockSenderTool()

    registry.register(sender_tool)
    assert registry.has_tool("sender_tool")

    unregistered = registry.unregister("sender_tool")
    assert unregistered is sender_tool
    assert not registry.has_tool("sender_tool")

    with pytest.raises(ToolNotFoundError):
        registry.unregister("sender_tool")


def test_list_tools_and_list_metadata() -> None:
    registry = ToolRegistry()
    url_tool = MockUrlTool()
    sender_tool = MockSenderTool()

    registry.register(url_tool)
    registry.register(sender_tool)

    tools = registry.list_tools()
    assert len(tools) == 2
    assert url_tool in tools
    assert sender_tool in tools

    metadata_list = registry.list_metadata()
    assert len(metadata_list) == 2
    names = [m.name for m in metadata_list]
    assert "url_tool" in names
    assert "sender_tool" in names


def test_get_metadata() -> None:
    registry = ToolRegistry()
    url_tool = MockUrlTool()
    registry.register(url_tool)

    meta = registry.get_metadata("url_tool")
    assert meta.name == "url_tool"
    assert meta.version == "1.0.0"
    assert meta.description == "Scans URLs in email body"

    with pytest.raises(ToolNotFoundError):
        registry.get_metadata("missing_tool")


def test_filter_by_capability() -> None:
    registry = ToolRegistry()
    url_tool = MockUrlTool()
    sender_tool = MockSenderTool()

    registry.register(url_tool)
    registry.register(sender_tool)

    url_tools = registry.filter_by_capability(ToolCapability.URL)
    assert url_tools == [url_tool]

    sender_tools = registry.filter_by_capability(ToolCapability.SENDER)
    assert sender_tools == [sender_tool]

    attachment_tools = registry.filter_by_capability(ToolCapability.ATTACHMENT)
    assert attachment_tools == []


def test_clear_registry() -> None:
    registry = ToolRegistry()
    registry.register(MockUrlTool())
    registry.register(MockSenderTool())

    assert len(registry.list_tools()) == 2
    registry.clear()
    assert len(registry.list_tools()) == 0
    assert not registry.has_tool("url_tool")
