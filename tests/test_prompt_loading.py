"""Unit tests for prompt loading infrastructure."""

from __future__ import annotations

import pytest

from src.planner.exceptions.planner_exceptions import PromptLoadError
from src.planner.prompts.prompt_provider import FileSystemPromptProvider


def test_load_system_prompt_success() -> None:
    """Verify that system prompt template loads and formats with available tools."""
    provider = FileSystemPromptProvider()
    prompt = provider.get_prompt(
        "system_prompt",
        available_tools="- TestTool: A mock tool description",
    )
    assert "TestTool" in prompt
    assert "deterministic tools" in prompt


def test_load_planning_prompt_success() -> None:
    """Verify that planning prompt template loads and formats with email context variables."""
    provider = FileSystemPromptProvider()
    prompt = provider.get_prompt(
        "planning_prompt",
        email_id="<abc@123>",
        email_subject="Verification Required",
        email_sender="sender@example.com",
        email_body_summary="This is a test email body summary.",
        execution_history="None",
        accumulated_evidence="None",
    )
    assert "<abc@123>" in prompt
    assert "Verification Required" in prompt
    assert "sender@example.com" in prompt


def test_load_nonexistent_prompt_fails() -> None:
    """Ensure that requesting a nonexistent template file raises PromptLoadError."""
    provider = FileSystemPromptProvider()
    with pytest.raises(PromptLoadError):
        provider.get_prompt("nonexistent_template")


def test_load_missing_variables_fails() -> None:
    """Ensure that omitting format variables required by a template raises PromptLoadError."""
    provider = FileSystemPromptProvider()
    # system_prompt expects 'available_tools' key
    with pytest.raises(PromptLoadError):
        provider.get_prompt("system_prompt")
