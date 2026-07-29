"""URLTool adapting Phase 4 UrlIntelligenceEngine to the AgentTool framework."""

from __future__ import annotations

import time

from src.analyzers.agent.contracts import AgentTool
from src.analyzers.agent.enterprise_intelligence import (
    EnterpriseIntelligenceService,
)
from src.analyzers.agent.evidence import EvidenceBuilder
from src.analyzers.url.engine import UrlIntelligenceEngine
from src.models.agent import (
    AgentState,
    ToolCapability,
    ToolEvidence,
    ToolExecutionStatus,
    ToolMetadata,
    ToolResult,
)
from src.models.evidence import EvidenceSeverity


class URLTool(AgentTool[AgentState]):
    """AgentTool wrapping existing Phase 4 UrlIntelligenceEngine without altering business logic."""

    def __init__(
        self,
        metadata: ToolMetadata | None = None,
        url_engine: UrlIntelligenceEngine | None = None,
        enterprise_intelligence: EnterpriseIntelligenceService | None = None,
    ) -> None:
        default_metadata = ToolMetadata(
            name="url_tool",
            description="Extracts, canonicalizes, and analyzes URLs for structural anomalies and shortener tricks.",
            version="1.0.0",
            capabilities=(ToolCapability.URL,),
            tags=("url", "hyperlink", "link_security"),
        )
        super().__init__(metadata or default_metadata)
        self._url_engine = url_engine or UrlIntelligenceEngine()
        self._enterprise_intelligence = (
            enterprise_intelligence or EnterpriseIntelligenceService()
        )

    def execute(self, input_data: AgentState) -> ToolResult:
        """Execute Phase 4 URL intelligence analysis on AgentState."""
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

        # Re-use existing UrlIntelligenceEngine without altering business logic
        url_results = self._url_engine.analyze(input_data.parsed_email)

        tool_evidence: list[ToolEvidence] = []
        shortened_count = 0
        anomaly_count = 0

        for item in url_results:
            if item.shortener.is_shortened:
                shortened_count += 1
            if item.suspicious_patterns:
                anomaly_count += len(item.suspicious_patterns)

            # Convert url evidence items
            for ev in item.evidence:
                built_ev = (
                    EvidenceBuilder.create()
                    .with_source(self.metadata.name)
                    .with_category(f"url_{ev.source}")
                    .with_severity(
                        EvidenceSeverity.MEDIUM
                        if item.suspicious_patterns
                        else EvidenceSeverity.INFO
                    )
                    .with_title(f"URL Observation ({ev.source})")
                    .with_description(f"Observed URL characteristic: {ev.detail}")
                    .with_metadata(
                        {"url": item.extracted.raw_value, "source": ev.source}
                    )
                    .build()
                )

                tool_evidence.append(
                    ToolEvidence(
                        category=built_ev.category,
                        detail=built_ev.description,
                        metadata=built_ev.metadata,
                    )
                )

            tool_evidence.extend(self._enterprise_evidence(item.extracted.raw_value))

        # Summary evidence
        summary_ev = (
            EvidenceBuilder.create()
            .with_source(self.metadata.name)
            .with_category("url_analysis")
            .with_severity(
                EvidenceSeverity.HIGH if anomaly_count > 0 else EvidenceSeverity.INFO
            )
            .with_title("URL Intelligence Processing Completed")
            .with_description(
                f"Analyzed {len(url_results)} extracted URLs for security signals."
            )
            .with_metadata(
                {
                    "total_urls_extracted": len(url_results),
                    "shortened_url_count": shortened_count,
                    "anomaly_count": anomaly_count,
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
                "total_urls_extracted": len(url_results),
                "shortened_url_count": shortened_count,
                "anomaly_count": anomaly_count,
            },
            evidence=tuple(tool_evidence),
            execution_time_ms=elapsed_ms,
        )

    def _enterprise_evidence(self, url: str) -> tuple[ToolEvidence, ...]:
        """Append optional URL reputation and infrastructure intelligence."""
        enrichment = self._enterprise_intelligence.enrich(url)
        evidence: list[ToolEvidence] = []
        for observation in enrichment.observations:
            evidence.append(
                ToolEvidence(
                    category=f"url_enterprise_{observation.provider_name}",
                    detail=observation.summary,
                    metadata={
                        "severity": (
                            EvidenceSeverity.HIGH.value
                            if observation.malicious
                            else EvidenceSeverity.INFO.value
                        ),
                        "confidence": observation.confidence,
                        "provider": observation.provider_name,
                        "url": url,
                        "from_cache": enrichment.from_cache,
                        **observation.metadata,
                    },
                )
            )
        for diagnostic in enrichment.diagnostics:
            evidence.append(
                ToolEvidence(
                    category="url_enterprise_diagnostic",
                    detail=(
                        f"{diagnostic.provider_name}: {diagnostic.reason}"
                    ),
                    metadata={
                        "severity": EvidenceSeverity.INFO.value,
                        "provider": diagnostic.provider_name,
                        "url": url,
                    },
                )
            )
        return tuple(evidence)
