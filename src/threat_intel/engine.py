"""Central ThreatIntelEngine executing threat intelligence enrichment and publishing IntelEnrichedEvent."""

from __future__ import annotations

from src.authentication.models import AuthenticationVerification
from src.config.logging import get_logger
from src.events.base_event import BaseEvent
from src.events.security_events import IntelEnrichedEvent
from src.interfaces.event_publisher import IEventPublisher
from src.parsing.models import ParsedEmail
from src.threat_intel.models import ThreatIntelEnrichmentResult
from src.threat_intel.pipeline import ThreatIntelPipeline
from src.transmission.models import TransmissionAnalysis

logger = get_logger("scamon.threat_intel.engine")


class ThreatIntelEngine:
    """Central Threat Intelligence Engine orchestrating enrichment and event dispatch."""

    def __init__(
        self,
        event_publisher: IEventPublisher | None = None,
        pipeline: ThreatIntelPipeline | None = None,
    ) -> None:
        self.event_publisher = event_publisher
        self.pipeline = pipeline or ThreatIntelPipeline()

    async def enrich_threat_intelligence(
        self,
        parsed: ParsedEmail,
        transmission: TransmissionAnalysis,
        auth: AuthenticationVerification,
    ) -> ThreatIntelEnrichmentResult:
        """Enrich email IOCs across threat feeds and publish IntelEnrichedEvent."""
        result = self.pipeline.enrich(parsed, transmission, auth)

        # Emit IntelEnrichedEvent (Reused security event contract)
        await self._publish_event(
            IntelEnrichedEvent(
                tenant_id=result.tenant_id,
                message_id=result.message_id,
                malicious_ioc_count=result.malicious_ioc_count,
                confidence_score=result.overall_confidence.confidence,
                matched_feeds=result.matched_feeds,
            )
        )

        logger.info(
            "Threat Intel enrichment completed for msg '%s': %d malicious IOCs, confidence=%.2f, feeds=%s in %.2fms",
            result.message_id,
            result.malicious_ioc_count,
            result.overall_confidence.confidence,
            result.matched_feeds,
            result.enrichment_time_ms,
        )
        return result

    async def _publish_event(self, event: BaseEvent) -> None:
        """Safely publish event if event publisher is configured."""
        if self.event_publisher:
            try:
                await self.event_publisher.publish(event)
            except Exception as exc:
                logger.error(
                    "Failed to publish threat intel event '%s': %s",
                    event.event_type,
                    exc,
                )
