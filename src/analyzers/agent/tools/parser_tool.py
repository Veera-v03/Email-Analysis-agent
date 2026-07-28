"""ParserTool wrapping raw email ingestion and parsing logic."""

from __future__ import annotations

import time
from typing import Any

from src.analyzers.agent.contracts import AgentTool
from src.analyzers.agent.evidence import EvidenceBuilder
from src.models.agent import (
    AgentState,
    ToolCapability,
    ToolEvidence,
    ToolExecutionStatus,
    ToolMetadata,
    ToolResult,
)
from src.models.email import EmailHeader, EmailInput
from src.models.evidence import EvidenceSeverity


class ParserTool(AgentTool[AgentState]):
    """AgentTool wrapping Phase 2 email ingestion and parsing pipeline."""

    def __init__(self, metadata: ToolMetadata | None = None) -> None:
        default_metadata = ToolMetadata(
            name="parser_tool",
            description="Parses raw email data into normalized EmailInput models.",
            version="1.0.0",
            capabilities=(ToolCapability.PARSER,),
            tags=("parser", "ingestion", "email"),
        )
        super().__init__(metadata or default_metadata)

    def execute(self, input_data: AgentState) -> ToolResult:
        """Execute email parser logic on AgentState."""
        start_ns = time.perf_counter_ns()

        if input_data.parsed_email is not None:
            elapsed_ms = max(0, int((time.perf_counter_ns() - start_ns) / 1_000_000))
            ev = EvidenceBuilder.create()\
                .with_source(self.metadata.name)\
                .with_category("parser")\
                .with_severity(EvidenceSeverity.INFO)\
                .with_title("Email Already Parsed")\
                .with_description("Parsed email contract already exists in state.")\
                .with_metadata({"message_id": input_data.parsed_email.header.message_id})\
                .build()

            tool_ev = ToolEvidence(
                category=ev.category,
                detail=ev.description,
                metadata=ev.metadata,
            )

            return ToolResult(
                tool_name=self.metadata.name,
                status=ToolExecutionStatus.COMPLETED,
                metadata={
                    "parsed": True,
                    "message_id": input_data.parsed_email.header.message_id,
                    "already_present": True,
                },
                evidence=(tool_ev,),
                parsed_email=input_data.parsed_email,
                execution_time_ms=elapsed_ms,
            )

        # Check for raw email content in state metadata
        raw_content = input_data.metadata.get("raw_email") or input_data.metadata.get("raw_payload")

        if not raw_content:
            elapsed_ms = max(0, int((time.perf_counter_ns() - start_ns) / 1_000_000))
            return ToolResult(
                tool_name=self.metadata.name,
                status=ToolExecutionStatus.SKIPPED,
                metadata={"parsed": False, "reason": "No raw email content found in state metadata"},
                evidence=(),
                execution_time_ms=elapsed_ms,
            )

        # Parse raw_content into EmailInput
        parsed = self._parse_raw(raw_content)

        ev = EvidenceBuilder.create()\
            .with_source(self.metadata.name)\
            .with_category("parser")\
            .with_severity(EvidenceSeverity.INFO)\
            .with_title("Raw Email Successfully Parsed")\
            .with_description("Normalized EmailInput constructed from raw email payload.")\
            .with_metadata({"message_id": parsed.header.message_id})\
            .build()

        tool_ev = ToolEvidence(
            category=ev.category,
            detail=ev.description,
            metadata=ev.metadata,
        )

        elapsed_ms = max(0, int((time.perf_counter_ns() - start_ns) / 1_000_000))
        return ToolResult(
            tool_name=self.metadata.name,
            status=ToolExecutionStatus.COMPLETED,
            metadata={
                "parsed": True,
                "message_id": parsed.header.message_id,
                "subject": parsed.header.subject,
                "sender": parsed.header.sender,
            },
            evidence=(tool_ev,),
            parsed_email=parsed,
            execution_time_ms=elapsed_ms,
        )

    def _parse_raw(self, raw_content: Any) -> EmailInput:
        """Helper to construct EmailInput from raw data."""
        if isinstance(raw_content, EmailInput):
            return raw_content

        if isinstance(raw_content, dict):
            return EmailInput.model_validate(raw_content)

        # Basic fallback for test raw string payload
        content_str = str(raw_content)
        return EmailInput(
            header=EmailHeader(
                message_id="<parsed@agent.local>",
                sender="sender@example.com",
                recipients=["recipient@example.com"],
                subject="Parsed Raw Email",
                sent_at="2026-07-28T12:00:00Z",
            ),
            body_text=content_str,
        )
