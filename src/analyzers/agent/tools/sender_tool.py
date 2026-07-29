"""SenderTool adapting Phase 3 SenderIntelligenceEngine to the AgentTool framework."""

from __future__ import annotations

import time

from src.analyzers.agent.contracts import AgentTool
from src.analyzers.agent.evidence import EvidenceBuilder
from src.analyzers.sender.engine import SenderIntelligenceEngine
from src.models.agent import (
    AgentState,
    ToolCapability,
    ToolEvidence,
    ToolExecutionStatus,
    ToolMetadata,
    ToolResult,
)
from src.models.evidence import EvidenceSeverity


class SenderTool(AgentTool[AgentState]):
    """AgentTool wrapping existing Phase 3 SenderIntelligenceEngine without changing business logic."""

    def __init__(
        self,
        metadata: ToolMetadata | None = None,
        sender_engine: SenderIntelligenceEngine | None = None,
    ) -> None:
        default_metadata = ToolMetadata(
            name="sender_tool",
            description="Analyzes sender identity, SPF/DKIM/DMARC authentication, display name, and domain features.",
            version="1.0.0",
            capabilities=(ToolCapability.SENDER,),
            tags=("sender", "authentication", "domain_analysis"),
        )
        super().__init__(metadata or default_metadata)
        self._sender_engine = sender_engine or SenderIntelligenceEngine()

    def execute(self, input_data: AgentState) -> ToolResult:
        """Execute Phase 3 sender intelligence analysis on AgentState."""
        start_ns = time.perf_counter_ns()

        if input_data.parsed_email is None:
            elapsed_ms = max(0, int((time.perf_counter_ns() - start_ns) / 1_000_000))
            return ToolResult(
                tool_name=self.metadata.name,
                status=ToolExecutionStatus.SKIPPED,
                metadata={"reason": "No parsed_email found in AgentState"},
                evidence=(),
                execution_time_ms=elapsed_ms,
            )

        # Re-use existing SenderIntelligenceEngine without altering business logic
        result = self._sender_engine.analyze(input_data.parsed_email)

        # Convert evidence emitted by SenderIntelligenceEngine to ToolEvidence
        tool_evidence: list[ToolEvidence] = []
        for item in result.evidence.items:
            ev = (
                EvidenceBuilder.create()
                .with_source(self.metadata.name)
                .with_category(item.evidence_type)
                .with_severity(item.severity)
                .with_title(item.title)
                .with_description(item.description)
                .with_metadata(item.metadata)
                .build()
            )

            tool_evidence.append(
                ToolEvidence(
                    category=ev.category,
                    detail=ev.description,
                    metadata=ev.metadata,
                )
            )

        # Add overall summary evidence
        summary_ev = (
            EvidenceBuilder.create()
            .with_source(self.metadata.name)
            .with_category("sender_analysis")
            .with_severity(EvidenceSeverity.INFO)
            .with_title("Sender Intelligence Completed")
            .with_description(
                f"Sender intelligence analysis completed for sender '{input_data.parsed_email.header.sender}'."
            )
            .with_metadata(
                {
                    "spf_status": result.authentication.spf.status.value,
                    "dkim_status": result.authentication.dkim.status.value,
                    "dmarc_status": result.authentication.dmarc.status.value,
                }
            )
            .build()
        )

        tool_evidence.append(
            ToolEvidence(
                category=summary_ev.category,
                detail=summary_ev.description,
                metadata=summary_ev.metadata,
            )
        )

        elapsed_ms = max(0, int((time.perf_counter_ns() - start_ns) / 1_000_000))
        return ToolResult(
            tool_name=self.metadata.name,
            status=ToolExecutionStatus.COMPLETED,
            metadata={
                "from_sender": input_data.parsed_email.header.sender,
                "spf_status": result.authentication.spf.status.value,
                "dkim_status": result.authentication.dkim.status.value,
                "dmarc_status": result.authentication.dmarc.status.value,
                "mismatch_count": len(result.consistency.mismatches),
            },
            evidence=tuple(tool_evidence),
            execution_time_ms=elapsed_ms,
        )
