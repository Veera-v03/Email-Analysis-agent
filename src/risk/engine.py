"""Central RiskAssessmentEngine for risk calculation, verdict assignment, and event publishing (Module 23)."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

from src.authentication.models import AuthenticationVerification
from src.config.logging import get_logger
from src.content_intelligence.models import ContentAnalysisResult
from src.events.base_event import BaseEvent
from src.events.security_events import RiskScoredEvent
from src.interfaces.event_publisher import IEventPublisher
from src.parsing.models import ParsedEmail
from src.risk.models import RiskAssessment
from src.risk.pipeline import RiskAssessmentPipeline
from src.risk.profiles import TenantRiskProfile
from src.threat_correlation.models import ThreatCorrelationResult
from src.threat_intel.models import ThreatIntelEnrichmentResult
from src.transmission.models import TransmissionAnalysis

logger = get_logger("scamon.risk.engine")


class RiskAssessmentEngine:
    """Central Risk Assessment Engine orchestrating pipeline execution and publishing RiskScoredEvent."""

    def __init__(
        self,
        event_publisher: IEventPublisher | None = None,
        pipeline: RiskAssessmentPipeline | None = None,
    ) -> None:
        self.event_publisher = event_publisher
        self.pipeline = pipeline or RiskAssessmentPipeline()

    async def assess_risk(
        self,
        parsed: ParsedEmail,
        transmission: TransmissionAnalysis,
        auth: AuthenticationVerification,
        intel: ThreatIntelEnrichmentResult,
        content_res: ContentAnalysisResult | None = None,
        url_res: Any | None = None,
        correlation_res: ThreatCorrelationResult | None = None,
        tenant_profile: TenantRiskProfile | None = None,
    ) -> RiskAssessment:
        """Assess email incident risk score (0-100), verdict, action, and publish RiskScoredEvent."""
        assessment = self.pipeline.assess_risk(
            parsed=parsed,
            transmission=transmission,
            auth=auth,
            intel=intel,
            content_res=content_res,
            url_res=url_res,
            correlation_res=correlation_res,
            tenant_profile=tenant_profile,
        )

        # Emit RiskScoredEvent (Reused security event contract)
        await self._publish_event(
            RiskScoredEvent(
                tenant_id=assessment.tenant_id,
                incident_id=uuid4(),
                message_id=assessment.message_id,
                risk_score=assessment.risk_score,
                verdict=assessment.verdict,
                threat_categories=assessment.threat_categories,
                recommended_action=assessment.recommended_action,
                explainability_summary=assessment.explainability_summary,
            )
        )

        logger.info(
            "Risk assessment completed for msg '%s': score=%d/100, prob=%.4f, verdict=%s, profile=%s, action=%s in %.2fms",
            assessment.message_id,
            assessment.risk_score,
            assessment.calibrated_probability,
            assessment.verdict.value,
            assessment.tenant_profile,
            assessment.recommended_action.value,
            assessment.assessment_time_ms,
        )
        return assessment

    async def _publish_event(self, event: BaseEvent) -> None:
        """Safely publish event if event publisher is configured."""
        if self.event_publisher:
            try:
                await self.event_publisher.publish(event)
            except Exception as exc:
                logger.error(
                    "Failed to publish risk event '%s': %s",
                    event.event_type,
                    exc,
                )
