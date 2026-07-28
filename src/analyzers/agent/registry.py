"""Tool registry for managing available agent tools."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from src.analyzers.agent.contracts import AgentTool
from src.analyzers.agent.exceptions import DuplicateToolError, ToolNotFoundError
from src.models.agent import ToolCapability, ToolMetadata


class IToolRegistry(ABC):
    """Abstract interface for managing registered agent tools."""

    @abstractmethod
    def register(self, tool: AgentTool[Any]) -> None:
        """Register an AgentTool instance."""

    @abstractmethod
    def unregister(self, tool_name: str) -> AgentTool[Any]:
        """Remove and return a registered AgentTool instance by name."""

    @abstractmethod
    def get(self, tool_name: str) -> AgentTool[Any]:
        """Retrieve a registered AgentTool instance by name."""

    @abstractmethod
    def has_tool(self, tool_name: str) -> bool:
        """Check if a tool with the given name is registered."""

    @abstractmethod
    def list_tools(self) -> list[AgentTool[Any]]:
        """List all registered tool instances."""

    @abstractmethod
    def list_metadata(self) -> list[ToolMetadata]:
        """List metadata for all registered tools."""

    @abstractmethod
    def get_metadata(self, tool_name: str) -> ToolMetadata:
        """Retrieve metadata for a specific registered tool by name."""

    @abstractmethod
    def filter_by_capability(self, capability: ToolCapability) -> list[AgentTool[Any]]:
        """Filter registered tools by capability."""

    @abstractmethod
    def clear(self) -> None:
        """Unregister all tools from the registry."""


class ToolRegistry(IToolRegistry):
    """Concrete tool registry for registering and discovering agent tools.

    Registry is strictly generic and depends only on AgentTool abstractions.
    It performs no tool execution logic.
    """

    def __init__(self) -> None:
        self._tools: dict[str, AgentTool[Any]] = {}

    def register(self, tool: AgentTool[Any]) -> None:
        """Register an AgentTool instance.

        Raises:
            DuplicateToolError: If a tool with the same name is already registered.
            TypeError: If the object is not an instance of AgentTool.
        """
        if not isinstance(tool, AgentTool):
            raise TypeError(f"Object {tool} must be an instance of AgentTool.")

        tool_name = tool.metadata.name
        if tool_name in self._tools:
            raise DuplicateToolError(tool_name)

        self._tools[tool_name] = tool

    def unregister(self, tool_name: str) -> AgentTool[Any]:
        """Remove and return a registered tool by name.

        Raises:
            ToolNotFoundError: If no tool with tool_name is registered.
        """
        if tool_name not in self._tools:
            raise ToolNotFoundError(tool_name)

        return self._tools.pop(tool_name)

    def get(self, tool_name: str) -> AgentTool[Any]:
        """Retrieve a registered tool by name.

        Raises:
            ToolNotFoundError: If no tool with tool_name is registered.
        """
        if tool_name not in self._tools:
            raise ToolNotFoundError(tool_name)

        return self._tools[tool_name]

    def has_tool(self, tool_name: str) -> bool:
        """Check if a tool with the given name is registered."""
        return tool_name in self._tools

    def list_tools(self) -> list[AgentTool[Any]]:
        """List all currently registered tool instances."""
        return list(self._tools.values())

    def list_metadata(self) -> list[ToolMetadata]:
        """List metadata for all registered tools."""
        return [tool.metadata for tool in self._tools.values()]

    def get_metadata(self, tool_name: str) -> ToolMetadata:
        """Retrieve metadata for a specific registered tool by name.

        Raises:
            ToolNotFoundError: If no tool with tool_name is registered.
        """
        tool = self.get(tool_name)
        return tool.metadata

    def filter_by_capability(self, capability: ToolCapability) -> list[AgentTool[Any]]:
        """Filter registered tools by capability."""
        return [
            tool
            for tool in self._tools.values()
            if capability in tool.metadata.capabilities
        ]

    def clear(self) -> None:
        """Unregister all tools from the registry."""
        self._tools.clear()
