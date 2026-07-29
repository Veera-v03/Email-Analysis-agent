"""Planner-selectable tool for optional normalized IOC reputation enrichment."""

from __future__ import annotations

from src.analyzers.agent.contracts import AgentTool
from src.models.agent import (
    AgentState,
    ToolCapability,
    ToolExecutionStatus,
    ToolMetadata,
    ToolResult,
)
from src.security_intelligence.ioc.ioc_extractor import IOCExtractor
from src.security_intelligence.threat_intel.framework import (
    ThreatIntelligenceFramework,
    ThreatIntelTargetType,
)


class ThreatIntelligenceTool(AgentTool[AgentState]):
    """Enrich email IOCs using injected providers without changing tool flow."""

    def __init__(
        self,
        metadata: ToolMetadata | None = None,
        framework: ThreatIntelligenceFramework | None = None,
        extractor: IOCExtractor | None = None,
    ) -> None:
        super().__init__(
            metadata
            or ToolMetadata(
                name="threat_intelligence_tool",
                description=(
                    "Enriches extracted IOCs with optional threat intelligence."
                ),
                version="1.0.0",
                capabilities=(
                    ToolCapability.URL,
                    ToolCapability.SENDER,
                    ToolCapability.ATTACHMENT,
                ),
                tags=("threat_intelligence", "ioc", "reputation"),
            )
        )
        self._framework = framework or ThreatIntelligenceFramework()
        self._extractor = extractor or IOCExtractor()

    def execute(self, input_data: AgentState) -> ToolResult:
        if input_data.parsed_email is None:
            return ToolResult(
                tool_name=self.metadata.name,
                status=ToolExecutionStatus.SKIPPED,
                metadata={"reason": "No parsed email available."},
            )
        email = input_data.parsed_email
        iocs = self._extractor.extract_iocs(
            f"{email.header.sender}\n{email.header.subject}\n{email.body_text}"
        )
        domain = email.header.sender.rsplit("@", 1)[-1]
        targets: list[tuple[str, ThreatIntelTargetType]] = [
            (domain, ThreatIntelTargetType.DOMAIN),
            *[(item, ThreatIntelTargetType.IP) for item in iocs["ips"]],
            *[(item, ThreatIntelTargetType.DOMAIN) for item in iocs["domains"]],
            *[(item, ThreatIntelTargetType.URL) for item in iocs["urls"]],
            *[(item, ThreatIntelTargetType.HASH) for item in iocs["hashes"]],
            *[(item, ThreatIntelTargetType.EMAIL) for item in iocs["emails"]],
        ]
        unique_targets = tuple(dict.fromkeys(targets))
        evidence = tuple(
            item
            for target, target_type in unique_targets
            for item in self._framework.to_evidence(target, target_type)
        )
        return ToolResult(
            tool_name=self.metadata.name,
            status=ToolExecutionStatus.COMPLETED,
            metadata={"iocs_enriched": len(unique_targets)},
            evidence=evidence,
        )
