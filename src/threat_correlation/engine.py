"""Central ThreatCorrelationEngine executing pipeline and emitting ThreatCorrelatedEvent."""

from __future__ import annotations

from typing import Any

from src.authentication.models import AuthenticationVerification
from src.config.logging import get_logger
from src.content_intelligence.models import ContentAnalysisResult
from src.events.security_events import ThreatCorrelatedEvent
from src.interfaces.event_publisher import IEventPublisher
from src.parsing.models import ParsedEmail
from src.threat_correlation.models import ThreatCorrelationResult
from src.threat_correlation.pipeline import ThreatCorrelationPipeline
from src.threat_intel.models import ThreatIntelEnrichmentResult
from src.transmission.models import TransmissionAnalysis
from src.url_intelligence.models import URLAnalysisResult

logger = get_logger("scamon.threat_correlation.engine")


class ThreatCorrelationEngine:
    """Central engine executing Threat Correlation Pipeline and emitting event contracts."""

    def __init__(
        self,
        event_publisher: IEventPublisher | None = None,
        pipeline: ThreatCorrelationPipeline | None = None,
    ) -> None:
        self.event_publisher = event_publisher
        self.pipeline = pipeline or ThreatCorrelationPipeline()

    async def correlate_threats(
        self,
        parsed: ParsedEmail,
        transmission: TransmissionAnalysis | None = None,
        auth: AuthenticationVerification | None = None,
        intel: ThreatIntelEnrichmentResult | None = None,
        content_res: ContentAnalysisResult | None = None,
        url_res: URLAnalysisResult | None = None,
    ) -> ThreatCorrelationResult:
        """Execute complete threat correlation, campaign clustering, and event emission."""
        result = self.pipeline.correlate(
            parsed=parsed,
            transmission=transmission,
            auth=auth,
            intel=intel,
            content_res=content_res,
            url_res=url_res,
        )

        if self.event_publisher:
            try:
                await self.event_publisher.publish(
                    ThreatCorrelatedEvent(
                        tenant_id=result.tenant_id,
                        message_id=result.message_id,
                        campaign_detected=result.campaign_detected,
                        campaign_score=result.campaign_score,
                        correlated_iocs_count=result.relationship_graph.total_nodes,
                        mitre_technique_count=len(result.mitre_techniques),
                    )
                )
            except Exception as exc:
                logger.debug(
                    "Event publishing for ThreatCorrelatedEvent failed: %s", exc
                )

        logger.info(
            "Threat correlation completed for msg '%s': campaign_detected=%s (score=%.1f), nodes=%d, MITRE_techniques=%d in %.2fms",
            result.message_id,
            result.campaign_detected,
            result.campaign_score,
            result.relationship_graph.total_nodes,
            len(result.mitre_techniques),
            result.execution_time_ms,
        )
        return result
