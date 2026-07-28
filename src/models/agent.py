"""Core models for the reusable Phase 5 agent-tool foundation."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, StrictStr, model_validator

from src.models.email import EmailInput
from src.models.evidence import Evidence, EvidenceCollection, EvidenceSeverity


class ToolExecutionStatus(StrEnum):
    """Describe the outcome of a deterministic tool execution."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class ToolCapability(StrEnum):
    """Describe which domain a future tool is intended to serve."""

    PARSER = "parser"
    URL = "url"
    SENDER = "sender"
    ATTACHMENT = "attachment"
    CONTENT = "content"


class ToolMetadata(BaseModel):
    """Describe the capabilities and identity of a reusable tool."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    name: StrictStr = Field(min_length=1, max_length=128)
    description: StrictStr = Field(min_length=1, max_length=1024)
    version: StrictStr = Field(min_length=1, max_length=64)
    capabilities: tuple[ToolCapability, ...] = Field(default_factory=tuple)
    tags: tuple[StrictStr, ...] = Field(default_factory=tuple)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ToolEvidence(BaseModel):
    """Legacy tool-evidence contract retained for backwards compatibility.

    New consumers should use :attr:`ToolResult.evidence_collection`, which
    contains the unified :class:`~src.models.evidence.Evidence` records.
    """

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    category: StrictStr = Field(min_length=1, max_length=128)
    detail: StrictStr = Field(min_length=1, max_length=1024)
    metadata: dict[str, Any] = Field(default_factory=dict)

    def to_evidence(self, source: str) -> Evidence:
        """Adapt this legacy record to the canonical evidence schema."""
        raw_severity = self.metadata.get("severity", EvidenceSeverity.INFO.value)
        try:
            severity = EvidenceSeverity(str(raw_severity).lower())
        except ValueError:
            severity = EvidenceSeverity.INFO
        confidence = self.metadata.get("confidence")
        return Evidence(
            evidence_type=self.category,
            category=self.category,
            title=self.category.replace("_", " ").title(),
            description=self.detail,
            severity=severity,
            source=source,
            confidence=float(confidence) if isinstance(confidence, (int, float)) else None,
            metadata=self.metadata,
        )


class ToolErrorInfo(BaseModel):
    """Represent a structured tool-level error for downstream handling."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    code: StrictStr = Field(min_length=1, max_length=128)
    message: StrictStr = Field(min_length=1, max_length=1024)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ToolResult(BaseModel):
    """Represent one tool execution outcome for future planner reasoning.

    ``evidence`` remains available to existing integrations.  The canonical,
    serializable evidence output is ``evidence_collection``.
    """

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    tool_name: StrictStr = Field(min_length=1, max_length=128)
    status: ToolExecutionStatus
    metadata: dict[str, Any] = Field(default_factory=dict)
    evidence: tuple[ToolEvidence, ...] = Field(default=())
    evidence_collection: EvidenceCollection = Field(default_factory=EvidenceCollection)
    parsed_email: EmailInput | None = None
    execution_time_ms: StrictInt = Field(default=0, ge=0)
    error: ToolErrorInfo | None = None

    @model_validator(mode="before")
    @classmethod
    def _populate_canonical_evidence(cls, data: Any) -> Any:
        """Guarantee unified evidence for legacy and newly migrated tools."""
        if not isinstance(data, dict):
            return data
        supplied_collection = data.get("evidence_collection")
        if supplied_collection:
            return data
        legacy_evidence = data.get("evidence", ())
        if not legacy_evidence:
            return data
        tool_name = str(data.get("tool_name", "agent_tool"))
        canonical_items = tuple(
            item.to_evidence(tool_name)
            if isinstance(item, ToolEvidence)
            else ToolEvidence.model_validate(item).to_evidence(tool_name)
            for item in legacy_evidence
        )
        return {**data, "evidence_collection": EvidenceCollection(items=canonical_items)}


class ExecutionRecord(BaseModel):
    """Represent one historical tool execution step in the agent workflow."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    step_number: StrictInt = Field(ge=1)
    tool_name: StrictStr = Field(min_length=1, max_length=128)
    status: ToolExecutionStatus
    timestamp: StrictStr = Field(min_length=1, max_length=64)
    execution_time_ms: StrictInt = Field(ge=0)
    details: dict[str, Any] = Field(default_factory=dict)


class PlanningDecision(BaseModel):
    """Placeholder model for future LLM planner decisions and reasoning."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    decision_id: StrictStr = Field(min_length=1, max_length=128)
    target_tool: StrictStr | None = Field(default=None, max_length=128)
    reasoning: StrictStr = Field(default="", max_length=4096)
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    is_final: StrictBool = Field(default=False)
    timestamp: StrictStr = Field(min_length=1, max_length=64)
    metadata: dict[str, Any] = Field(default_factory=dict)


class AgentState(BaseModel):
    """Central agent state serving as the single source of truth.

    Immutable Pydantic model storing parsed email information, tool results,
    accumulated evidence, execution history, errors, and future planner
    placeholders.
    """

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    state_id: StrictStr = Field(min_length=1, max_length=128)
    parsed_email: EmailInput | None = Field(default=None)
    tool_results: dict[StrictStr, ToolResult] = Field(default_factory=dict)
    accumulated_evidence: tuple[ToolEvidence, ...] = Field(default_factory=tuple)
    evidence: EvidenceCollection = Field(default_factory=EvidenceCollection)
    execution_history: tuple[ExecutionRecord, ...] = Field(default_factory=tuple)
    errors: tuple[ToolErrorInfo, ...] = Field(default_factory=tuple)
    planning_decisions: tuple[PlanningDecision, ...] = Field(default_factory=tuple)
    created_at: StrictStr = Field(min_length=1, max_length=64)
    updated_at: StrictStr = Field(min_length=1, max_length=64)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def create(
        cls,
        parsed_email: EmailInput | None = None,
        state_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> AgentState:
        """Factory helper to create a new AgentState with UTC timestamps."""
        now = datetime.now(UTC).isoformat()
        sid = state_id or f"state_{uuid.uuid4().hex[:12]}"
        return cls(
            state_id=sid,
            parsed_email=parsed_email,
            created_at=now,
            updated_at=now,
            metadata=metadata or {},
        )

    def with_parsed_email(self, email: EmailInput) -> AgentState:
        """Return a new state copy with parsed email attached."""
        now = datetime.now(UTC).isoformat()
        return self.model_copy(
            update={
                "parsed_email": email,
                "updated_at": now,
            }
        )

    def with_tool_result(
        self,
        result: ToolResult,
        execution_details: dict[str, Any] | None = None,
    ) -> AgentState:
        """Return a new state copy recording a tool execution result."""
        now = datetime.now(UTC).isoformat()
        new_results = dict(self.tool_results)
        new_results[result.tool_name] = result

        new_evidence = self.accumulated_evidence + result.evidence
        canonical_evidence = self.evidence.add(result.evidence_collection.items)

        record = ExecutionRecord(
            step_number=len(self.execution_history) + 1,
            tool_name=result.tool_name,
            status=result.status,
            timestamp=now,
            execution_time_ms=result.execution_time_ms,
            details=execution_details or {},
        )
        new_history = self.execution_history + (record,)

        new_errors = self.errors
        if result.error is not None:
            new_errors = new_errors + (result.error,)

        updates: dict[str, Any] = {
            "tool_results": new_results,
            "accumulated_evidence": new_evidence,
            "evidence": canonical_evidence,
            "execution_history": new_history,
            "errors": new_errors,
            "updated_at": now,
        }
        if result.parsed_email is not None:
            updates["parsed_email"] = result.parsed_email

        return self.model_copy(
            update={
                **updates,
            }
        )

    def with_evidence(
        self,
        evidence: ToolEvidence | tuple[ToolEvidence, ...],
    ) -> AgentState:
        """Return a new state copy with additional evidence attached."""
        now = datetime.now(UTC).isoformat()
        items = (evidence,) if isinstance(evidence, ToolEvidence) else evidence
        return self.model_copy(
            update={
                "accumulated_evidence": self.accumulated_evidence + items,
                "evidence": self.evidence.add(
                    tuple(item.to_evidence("agent_state") for item in items)
                ),
                "updated_at": now,
            }
        )

    def with_error(self, error: ToolErrorInfo) -> AgentState:
        """Return a new state copy with an error recorded."""
        now = datetime.now(UTC).isoformat()
        return self.model_copy(
            update={
                "errors": self.errors + (error,),
                "updated_at": now,
            }
        )

    def with_planning_decision(self, decision: PlanningDecision) -> AgentState:
        """Return a new state copy with a planning decision attached."""
        now = datetime.now(UTC).isoformat()
        return self.model_copy(
            update={
                "planning_decisions": self.planning_decisions + (decision,),
                "updated_at": now,
            }
        )

    def to_dict(self) -> dict[str, Any]:
        """Dump the state model to a Python dictionary."""
        return self.model_dump()

    def to_json(self) -> str:
        """Dump the state model to a JSON string."""
        return self.model_dump_json()

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AgentState:
        """Parse an AgentState instance from a dictionary."""
        return cls.model_validate(data)

    @classmethod
    def from_json(cls, json_str: str) -> AgentState:
        """Parse an AgentState instance from a JSON string."""
        return cls.model_validate_json(json_str)

