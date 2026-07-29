"""Unit tests for planner Pydantic models."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from src.planner.models.planner import (
    ExecutionPlan,
    ExecutionStep,
    ExecutionStrategy,
    PlannerContext,
    PlanningOptions,
    ToolSelection,
)


def test_execution_strategy_enum() -> None:
    """Ensure strategy choices exist and map correct string values."""
    assert ExecutionStrategy.TARGETED.value == "targeted"
    assert ExecutionStrategy.SEQUENTIAL.value == "sequential"
    assert ExecutionStrategy.FULL.value == "full"


def test_execution_step_validates() -> None:
    """Ensure a valid tool step parses correctly and fields are strictly typed."""
    step = ExecutionStep(
        tool="SenderTool",
        priority=1,
        reason="Verify sender authenticity",
    )
    assert step.tool == "SenderTool"
    assert step.priority == 1
    assert step.reason == "Verify sender authenticity"

    # Missing fields
    with pytest.raises(ValidationError):
        ExecutionStep(tool="SenderTool", priority=1)  # type: ignore

    # Invalid types (strict validation)
    with pytest.raises(ValidationError):
        ExecutionStep(tool="SenderTool", priority="1", reason="Reason")  # type: ignore


def test_execution_plan_validates() -> None:
    """Ensure a valid plan with nested steps parses and validates."""
    data = {
        "goal": "Analyze incoming email",
        "strategy": "targeted",
        "steps": [
            {"tool": "SenderTool", "priority": 1, "reason": "Check sender"},
            {"tool": "URLTool", "priority": 2, "reason": "Check URLs"},
        ],
        "confidence": 0.95,
    }
    plan = ExecutionPlan.model_validate(data)
    assert plan.goal == "Analyze incoming email"
    assert plan.strategy == ExecutionStrategy.TARGETED
    assert len(plan.steps) == 2
    assert plan.steps[0].tool == "SenderTool"
    assert plan.confidence == 0.95


def test_planner_context_validates() -> None:
    """Verify serialization helper models for tools and state context."""
    tool = ToolSelection(
        name="ParserTool",
        description="Parses emails",
        capabilities=("parser",),
    )
    context = PlannerContext(
        email_id="<test@id>",
        email_subject="Test",
        email_sender="sender@example.com",
        email_body_summary="Body",
        available_tools=(tool,),
        execution_history=(
            {"step_number": 1, "tool_name": "ParserTool", "status": "completed"},
        ),
        accumulated_evidence=(),
    )
    assert context.email_id == "<test@id>"
    assert len(context.available_tools) == 1
    assert context.available_tools[0].name == "ParserTool"


def test_planning_options_defaults() -> None:
    """Verify options validate defaults and respect boundaries."""
    opts = PlanningOptions()
    assert opts.temperature == 0.0
    assert opts.max_tokens == 1024
    assert opts.timeout == 30.0
    assert opts.retry_count == 3
    assert opts.retry_delay == 1.0

    # Out of range temperature
    with pytest.raises(ValidationError):
        PlanningOptions(temperature=-1.0)
    with pytest.raises(ValidationError):
        PlanningOptions(temperature=3.0)
