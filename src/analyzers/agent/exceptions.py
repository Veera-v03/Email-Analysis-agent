"""Common exception types for the reusable agent-tool foundation."""

from __future__ import annotations

from typing import Any


class ToolValidationError(ValueError):
    """Raised when a tool receives invalid input or state."""

    def __init__(
        self,
        message: str,
        *,
        code: str = "validation_error",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.details = details or {}


class ToolExecutionError(RuntimeError):
    """Raised when a tool cannot complete execution successfully."""

    def __init__(
        self,
        message: str,
        *,
        code: str = "execution_error",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.details = details or {}


class ToolRegistryError(Exception):
    """Base exception for tool registry operations."""

    def __init__(
        self,
        message: str,
        *,
        code: str = "registry_error",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.details = details or {}


class DuplicateToolError(ToolRegistryError, ValueError):
    """Raised when attempting to register a tool with an already existing name."""

    def __init__(
        self,
        tool_name: str,
        message: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        msg = message or f"Tool with name '{tool_name}' is already registered."
        super().__init__(
            msg,
            code="duplicate_tool_error",
            details=details or {"tool_name": tool_name},
        )
        self.tool_name = tool_name


class ToolNotFoundError(ToolRegistryError, KeyError):
    """Raised when looking up or unregistering a non-existent tool."""

    def __init__(
        self,
        tool_name: str,
        message: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        msg = message or f"Tool with name '{tool_name}' was not found in registry."
        super().__init__(
            msg,
            code="tool_not_found_error",
            details=details or {"tool_name": tool_name},
        )
        self.tool_name = tool_name

