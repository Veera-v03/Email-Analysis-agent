"""SenderTool adapting Phase 3 SenderIntelligenceEngine to the AgentTool framework."""

from __future__ import annotations

import time
from email.utils import parseaddr

from src.analyzers.agent.contracts import AgentTool
from src.analyzers.agent.enterprise_intelligence import (
    EnterpriseIntelligenceService,
)
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
from src.models.authentication import AuthenticationAnalysisResult, AuthenticationStatus
from src.models.evidence import EvidenceSeverity


class SenderTool(AgentTool[AgentState]):
    """AgentTool wrapping existing Phase 3 SenderIntelligenceEngine without changing business logic."""

    def __init__(
        self,
        metadata: ToolMetadata | None = None,
        sender_engine: SenderIntelligenceEngine | None = None,
        enterprise_intelligence: EnterpriseIntelligenceService | None = None,
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
        self._enterprise_intelligence = (
            enterprise_intelligence or EnterpriseIntelligenceService()
        )

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
        authentication_metadata = self._authentication_metadata(result.authentication)

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

        tool_evidence.extend(
            self._enterprise_evidence(input_data.parsed_email.header.sender)
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
            .with_metadata(authentication_metadata)
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
        mismatch_count = (
            len(result.consistency.mismatches) if result.consistency is not None else 0
        )
        return ToolResult(
            tool_name=self.metadata.name,
            status=ToolExecutionStatus.COMPLETED,
            metadata={
                "from_sender": input_data.parsed_email.header.sender,
                **authentication_metadata,
                "mismatch_count": mismatch_count,
            },
            evidence=tuple(tool_evidence),
            execution_time_ms=elapsed_ms,
        )

    @staticmethod
    def _authentication_metadata(
        authentication: AuthenticationAnalysisResult | None,
    ) -> dict[str, str]:
        """Return stable authentication statuses when analysis is unavailable."""
        if authentication is None:
            unknown_status = AuthenticationStatus.UNKNOWN.value
            return {
                "spf_status": unknown_status,
                "dkim_status": unknown_status,
                "dmarc_status": unknown_status,
            }

        return {
            "spf_status": authentication.spf.status.value,
            "dkim_status": authentication.dkim.status.value,
            "dmarc_status": authentication.dmarc.status.value,
        }

    def _enterprise_evidence(self, sender: str) -> tuple[ToolEvidence, ...]:
        """Append optional sender infrastructure intelligence as tool evidence."""
        mailbox = parseaddr(sender)[1]
        domain = mailbox.rsplit("@", 1)[-1].casefold() if "@" in mailbox else ""
        if not domain:
            return (
                ToolEvidence(
                    category="sender_enterprise_diagnostic",
                    detail="Sender infrastructure enrichment skipped: no sender domain.",
                    metadata={"severity": EvidenceSeverity.INFO.value},
                ),
            )

        enrichment = self._enterprise_intelligence.enrich(domain)
        evidence: list[ToolEvidence] = []
        for observation in enrichment.observations:
            evidence.append(
                ToolEvidence(
                    category=f"sender_enterprise_{observation.provider_name}",
                    detail=observation.summary,
                    metadata={
                        "severity": (
                            EvidenceSeverity.HIGH.value
                            if observation.malicious
                            else EvidenceSeverity.INFO.value
                        ),
                        "confidence": observation.confidence,
                        "provider": observation.provider_name,
                        "domain": domain,
                        "from_cache": enrichment.from_cache,
                        **observation.metadata,
                    },
                )
            )
        for diagnostic in enrichment.diagnostics:
            evidence.append(
                ToolEvidence(
                    category="sender_enterprise_diagnostic",
                    detail=(f"{diagnostic.provider_name}: {diagnostic.reason}"),
                    metadata={
                        "severity": EvidenceSeverity.INFO.value,
                        "provider": diagnostic.provider_name,
                        "domain": domain,
                    },
                )
            )
        return tuple(evidence)
