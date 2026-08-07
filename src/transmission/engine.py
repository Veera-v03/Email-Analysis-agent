"""Central TransmissionAnalysisEngine for header analysis and event publishing."""

from __future__ import annotations

from src.config.logging import get_logger
from src.events.base_event import BaseEvent
from src.events.transmission_events import (
    HeaderAnalysisCompletedEvent,
    HeaderAnomalyDetectedEvent,
)
from src.interfaces.event_publisher import IEventPublisher
from src.parsing.models import ParsedEmail
from src.transmission.models import TransmissionAnalysis
from src.transmission.pipeline import TransmissionAnalysisPipeline

logger = get_logger("scamon.transmission.engine")


class TransmissionAnalysisEngine:
    """Central engine executing header analysis and publishing transmission events."""

    def __init__(self, event_publisher: IEventPublisher | None = None) -> None:
        self.event_publisher = event_publisher
        self.pipeline = TransmissionAnalysisPipeline()

    async def analyze_transmission(self, parsed: ParsedEmail) -> TransmissionAnalysis:
        """Analyze ParsedEmail headers and publish transmission analysis events."""
        analysis = self.pipeline.analyze(parsed)

        # Emit HeaderAnalysisCompletedEvent
        await self._publish_event(
            HeaderAnalysisCompletedEvent(
                tenant_id=analysis.tenant_id,
                analysis_id=analysis.analysis_id,
                parsed_id=analysis.parsed_id,
                raw_email_id=analysis.raw_email_id,
                account_id=analysis.account_id,
                message_id=analysis.message_id,
                originating_ip=analysis.originating_ip,
                originating_country=analysis.originating_country,
                is_display_name_spoofed=analysis.sender_identity.is_display_name_spoofed,
                is_reply_to_mismatched=analysis.sender_identity.is_reply_to_mismatched,
                anomaly_count=len(analysis.anomalies),
                header_integrity_score=analysis.header_integrity_score,
                sender_authenticity_score=analysis.sender_authenticity_score,
                analysis_time_ms=analysis.analysis_time_ms,
            )
        )

        # Emit HeaderAnomalyDetectedEvent for high-risk or critical anomalies
        for anomaly in analysis.anomalies:
            if anomaly.severity in ("HIGH", "CRITICAL"):
                await self._publish_event(
                    HeaderAnomalyDetectedEvent(
                        tenant_id=analysis.tenant_id,
                        analysis_id=analysis.analysis_id,
                        parsed_id=analysis.parsed_id,
                        anomaly_code=anomaly.anomaly_code,
                        description=anomaly.description,
                        severity=anomaly.severity,
                        risk_score_impact=anomaly.risk_score_impact,
                    )
                )

        logger.info(
            "Transmission analysis completed for msg '%s' (anomalies: %d, integrity: %.2f)",
            analysis.message_id,
            len(analysis.anomalies),
            analysis.header_integrity_score,
        )
        return analysis

    async def _publish_event(self, event: BaseEvent) -> None:
        """Safely publish event if event publisher is configured."""
        if self.event_publisher:
            try:
                await self.event_publisher.publish(event)
            except Exception as exc:
                logger.error(
                    "Failed to publish transmission event '%s': %s",
                    event.event_type,
                    exc,
                )
