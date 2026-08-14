"""Central AIDecisionEngine executing decision planning and event dispatch."""

from __future__ import annotations

from src.ai_decision.models import DecisionPlan
from src.ai_decision.pipeline import AIDecisionPipeline
from src.config.logging import get_logger
from src.events.base_event import BaseEvent
from src.events.security_events import RiskScoredEvent
from src.interfaces.event_publisher import IEventPublisher
from src.risk.models import RiskAssessment

logger = get_logger("scamon.ai_decision.engine")


class AIDecisionEngine:
    """Central AI Decision Planner Engine orchestrating pipeline execution and event publishing."""

    def __init__(
        self,
        event_publisher: IEventPublisher | None = None,
        pipeline: AIDecisionPipeline | None = None,
    ) -> None:
        self.event_publisher = event_publisher
        self.pipeline = pipeline or AIDecisionPipeline()

    async def generate_decision_plan(self, assessment: RiskAssessment) -> DecisionPlan:
        """Generate structured AI DecisionPlan DTO for a RiskAssessment."""
        plan = await self.pipeline.plan_decision(assessment)

        # Emit event if publisher is present
        await self._publish_event(
            RiskScoredEvent(
                tenant_id=plan.tenant_id,
                incident_id=plan.plan_id,
                message_id=plan.message_id,
                risk_score=assessment.risk_score,
                verdict=assessment.verdict,
                threat_categories=assessment.threat_categories,
                recommended_action=assessment.recommended_action,
                explainability_summary=plan.executive_summary,
            )
        )

        logger.info(
            "AI Decision Planning completed for msg '%s' via %s: confidence=%.2f in %.2fms",
            plan.message_id,
            plan.prompt_metadata.provider_version,
            plan.ai_decision_confidence,
            plan.generation_time_ms,
        )
        return plan

    async def _publish_event(self, event: BaseEvent) -> None:
        """Safely publish event if event publisher is configured."""
        if self.event_publisher:
            try:
                await self.event_publisher.publish(event)
            except Exception as exc:
                logger.error(
                    "Failed to publish decision event '%s': %s",
                    event.event_type,
                    exc,
                )
