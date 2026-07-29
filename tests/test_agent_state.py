from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from src.models.agent import (
    AgentState,
    ExecutionRecord,
    PlanningDecision,
    ToolErrorInfo,
    ToolEvidence,
    ToolExecutionStatus,
    ToolResult,
)
from src.models.email import EmailHeader, EmailInput


def test_agent_state_creation_defaults() -> None:
    state = AgentState.create(state_id="state_123")

    assert state.state_id == "state_123"
    assert state.parsed_email is None
    assert state.tool_results == {}
    assert state.accumulated_evidence == ()
    assert state.evidence.items == ()
    assert state.execution_history == ()
    assert state.errors == ()
    assert state.planning_decisions == ()
    assert state.created_at != ""
    assert state.updated_at == state.created_at


def test_agent_state_immutability() -> None:
    state = AgentState.create()

    with pytest.raises((TypeError, ValidationError)):
        state.state_id = "new_id"


def test_with_parsed_email() -> None:
    initial_state = AgentState.create()
    sample_email = EmailInput(
        header=EmailHeader(
            message_id="<test@example.com>",
            sender="alice@example.com",
            recipients=["bob@example.com"],
            subject="Test Subject",
            sent_at="2026-07-28T10:00:00Z",
        ),
        body_text="Hello world",
    )

    new_state = initial_state.with_parsed_email(sample_email)

    assert new_state is not initial_state
    assert new_state.parsed_email == sample_email
    assert new_state.parsed_email.header.subject == "Test Subject"
    assert new_state.updated_at >= initial_state.updated_at


def test_with_tool_result_records_history_evidence_and_errors() -> None:
    state = AgentState.create()
    result = ToolResult(
        tool_name="url_analyzer",
        status=ToolExecutionStatus.FAILED,
        evidence=(
            ToolEvidence(
                category="suspicious_url",
                detail="Found malicious domain example.phish",
            ),
        ),
        execution_time_ms=42,
        error=ToolErrorInfo(
            code="network_timeout",
            message="Connection timed out while scanning domain",
        ),
    )

    updated_state = state.with_tool_result(result, execution_details={"attempt": 1})

    assert "url_analyzer" in updated_state.tool_results
    assert updated_state.tool_results["url_analyzer"] == result
    assert len(updated_state.accumulated_evidence) == 1
    assert updated_state.accumulated_evidence[0].category == "suspicious_url"
    assert updated_state.evidence.items[0].source == "url_analyzer"
    assert updated_state.evidence.items[0].category == "suspicious_url"
    assert len(updated_state.execution_history) == 1

    record: ExecutionRecord = updated_state.execution_history[0]
    assert record.step_number == 1
    assert record.tool_name == "url_analyzer"
    assert record.status is ToolExecutionStatus.FAILED
    assert record.execution_time_ms == 42
    assert record.details == {"attempt": 1}

    assert len(updated_state.errors) == 1
    assert updated_state.errors[0].code == "network_timeout"


def test_with_evidence_and_error_and_planning_decision() -> None:
    state = AgentState.create()

    ev = ToolEvidence(category="header", detail="SPF pass")
    state_ev = state.with_evidence(ev)
    assert len(state_ev.accumulated_evidence) == 1
    assert state_ev.accumulated_evidence[0].detail == "SPF pass"

    err = ToolErrorInfo(code="syntax_error", message="Malformed header")
    state_err = state_ev.with_error(err)
    assert len(state_err.errors) == 1

    decision = PlanningDecision(
        decision_id="dec_001",
        target_tool="attachment_analyzer",
        reasoning="Suspicious PDF attachment detected",
        confidence=0.95,
        is_final=False,
        timestamp="2026-07-28T12:00:00Z",
    )
    final_state = state_err.with_planning_decision(decision)
    assert len(final_state.planning_decisions) == 1
    assert final_state.planning_decisions[0].target_tool == "attachment_analyzer"
    assert final_state.planning_decisions[0].confidence == 0.95


def test_json_and_dict_serialization_roundtrip() -> None:
    sample_email = EmailInput(
        header=EmailHeader(
            message_id="<ser@example.com>",
            sender="sender@domain.com",
            recipients=["rcpt@domain.com"],
            subject="Serialization Test",
            sent_at="2026-07-28T10:00:00Z",
        ),
        body_text="Body content",
    )
    state = AgentState.create(parsed_email=sample_email, state_id="state_ser_1")

    # Dict roundtrip
    dict_data = state.to_dict()
    reconstructed_from_dict = AgentState.from_dict(dict_data)
    assert reconstructed_from_dict == state

    # JSON roundtrip
    json_str = state.to_json()
    reconstructed_from_json = AgentState.from_json(json_str)
    assert reconstructed_from_json == state
    assert json.loads(json_str)["state_id"] == "state_ser_1"
