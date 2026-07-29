"""ReportTool generating a consolidated summary report from AgentState."""

from __future__ import annotations

import time

from src.analyzers.agent.contracts import AgentTool
from src.analyzers.agent.evidence import EvidenceAggregator, EvidenceBuilder
from src.models.agent import (
    AgentState,
    ToolCapability,
    ToolEvidence,
    ToolExecutionStatus,
    ToolMetadata,
    ToolResult,
)
from src.models.evidence import EvidenceSeverity


class ReportTool(AgentTool[AgentState]):
    """AgentTool generating a consolidated summary report from all AgentState execution findings."""

    def __init__(self, metadata: ToolMetadata | None = None) -> None:
        default_metadata = ToolMetadata(
            name="report_tool",
            description="Generates a consolidated diagnostic report summarizing all tool results and evidence.",
            version="1.0.0",
            capabilities=(ToolCapability.CONTENT,),
            tags=("report", "summary", "diagnostics"),
        )
        super().__init__(metadata or default_metadata)

    def execute(self, input_data: AgentState) -> ToolResult:
        """Consolidate tool execution results and evidence into a structured diagnostic report."""
        start_ns = time.perf_counter_ns()

        # Aggregate and deduplicate all evidence using EvidenceAggregator
        evidence_collection = EvidenceAggregator.aggregate(
            list(input_data.evidence.items)
        )

        critical_count = len(
            evidence_collection.filter_by_severity(EvidenceSeverity.CRITICAL)
        )
        high_count = len(evidence_collection.filter_by_severity(EvidenceSeverity.HIGH))
        medium_count = len(
            evidence_collection.filter_by_severity(EvidenceSeverity.MEDIUM)
        )
        low_count = len(evidence_collection.filter_by_severity(EvidenceSeverity.LOW))
        info_count = len(evidence_collection.filter_by_severity(EvidenceSeverity.INFO))

        highest_severity = (
            EvidenceSeverity.CRITICAL
            if critical_count > 0
            else EvidenceSeverity.HIGH
            if high_count > 0
            else EvidenceSeverity.MEDIUM
            if medium_count > 0
            else EvidenceSeverity.LOW
            if low_count > 0
            else EvidenceSeverity.INFO
        )

        report_ev = (
            EvidenceBuilder.create()
            .with_source(self.metadata.name)
            .with_category("diagnostic_report")
            .with_severity(highest_severity)
            .with_title("Consolidated Analysis Diagnostic Report")
            .with_description(
                f"Completed analysis across {len(input_data.tool_results)} tools. "
                f"Generated {len(evidence_collection.items)} unique evidence items "
                f"(Highest severity: {highest_severity.value.upper()})."
            )
            .with_metadata(
                {
                    "tools_executed": list(input_data.tool_results.keys()),
                    "total_evidence_count": len(evidence_collection.items),
                    "critical_count": critical_count,
                    "high_count": high_count,
                    "medium_count": medium_count,
                    "low_count": low_count,
                    "info_count": info_count,
                    "highest_severity": highest_severity.value,
                }
            )
            .build()
        )

        tool_ev = ToolEvidence(
            category=report_ev.category,
            detail=report_ev.description,
            metadata=report_ev.metadata,
        )

        elapsed_ms = max(0, int((time.perf_counter_ns() - start_ns) / 1_000_000))
        return ToolResult(
            tool_name=self.metadata.name,
            status=ToolExecutionStatus.COMPLETED,
            metadata={
                "tools_executed_count": len(input_data.tool_results),
                "total_evidence_count": len(evidence_collection.items),
                "highest_severity": highest_severity.value,
                "critical_count": critical_count,
                "high_count": high_count,
            },
            evidence=(tool_ev,),
            execution_time_ms=elapsed_ms,
        )
