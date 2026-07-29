"""Planner-selectable adapter for the existing campaign correlation engine."""

from __future__ import annotations

from hashlib import sha256

from src.analyzers.agent.contracts import AgentTool
from src.models.agent import (
    AgentState,
    ToolCapability,
    ToolEvidence,
    ToolExecutionStatus,
    ToolMetadata,
    ToolResult,
)
from src.security_intelligence.campaign.campaign_correlation import (
    CampaignCorrelationEngine,
)
from src.security_intelligence.ioc.ioc_extractor import IOCExtractor


class CampaignCorrelationTool(AgentTool[AgentState]):
    """Emit campaign evidence based on historical investigations in the tenant."""

    def __init__(
        self,
        metadata: ToolMetadata | None = None,
        engine: CampaignCorrelationEngine | None = None,
        extractor: IOCExtractor | None = None,
    ) -> None:
        super().__init__(
            metadata
            or ToolMetadata(
                name="campaign_correlation_tool",
                description=(
                    "Correlates current IOCs with historical tenant investigations."
                ),
                version="1.0.0",
                capabilities=(ToolCapability.CONTENT,),
                tags=("campaign", "correlation", "memory"),
            )
        )
        self._engine = engine or CampaignCorrelationEngine()
        self._extractor = extractor or IOCExtractor()

    def execute(self, input_data: AgentState) -> ToolResult:
        email = input_data.parsed_email
        org_id = input_data.metadata.get("organization_id")
        if email is None or not isinstance(org_id, str) or not org_id:
            return ToolResult(
                tool_name=self.metadata.name,
                status=ToolExecutionStatus.SKIPPED,
                metadata={
                    "reason": "Parsed email or organization context unavailable."
                },
            )
        iocs = self._extractor.extract_iocs(
            f"{email.header.subject}\n{email.body_text}"
        )
        result = self._engine.correlate_investigation(
            org_id=org_id,
            sender=email.header.sender,
            subject=email.header.subject,
            extracted_iocs=iocs,
        )
        if not result["campaign_detected"]:
            return ToolResult(
                tool_name=self.metadata.name,
                status=ToolExecutionStatus.COMPLETED,
                metadata={"campaign_detected": False},
            )
        campaign_id = self._campaign_id(
            email.header.sender, result["indicators_matched"]
        )
        evidence = ToolEvidence(
            category="campaign_correlation",
            detail=(
                f"Campaign {campaign_id} correlated "
                f"{len(result['correlated_investigations'])} "
                "historical investigations using shared indicators."
            ),
            metadata={
                "severity": "high" if result["campaign_score"] >= 4 else "medium",
                "confidence": min(1.0, float(result["campaign_score"]) / 10.0),
                "campaign_id": campaign_id,
                "campaign_score": result["campaign_score"],
                "shared_indicators": result["indicators_matched"],
                "historical_matches": result["correlated_investigations"],
            },
        )
        return ToolResult(
            tool_name=self.metadata.name,
            status=ToolExecutionStatus.COMPLETED,
            metadata={"campaign_detected": True, "campaign_id": campaign_id},
            evidence=(evidence,),
        )

    @staticmethod
    def _campaign_id(sender: str, indicators: list[str]) -> str:
        seed = f"{sender.casefold()}:{','.join(sorted(indicators))}"
        return f"campaign_{sha256(seed.encode('utf-8')).hexdigest()[:12]}"
