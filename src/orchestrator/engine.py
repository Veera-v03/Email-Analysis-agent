"""Central OrchestratorEngine executing email pipeline and emitting lifecycle events."""

from __future__ import annotations

import asyncio

from src.config.logging import get_logger
from src.database.models import RawEmail
from src.events.base_event import BaseEvent
from src.events.pipeline_events import (
    PipelineCompletedEvent,
    PipelineFailedEvent,
    PipelineStartedEvent,
)
from src.interfaces.event_publisher import IEventPublisher
from src.orchestrator.models import EmailAnalysisResult, PipelineContext
from src.orchestrator.orchestrator import EmailSecurityPipelineOrchestrator

logger = get_logger("scamon.orchestrator.engine")


class OrchestratorEngine:
    """Central Orchestrator Engine orchestrating end-to-end email analysis and publishing lifecycle events."""

    def __init__(
        self,
        event_publisher: IEventPublisher | None = None,
        orchestrator: EmailSecurityPipelineOrchestrator | None = None,
    ) -> None:
        self.event_publisher = event_publisher
        self.orchestrator = orchestrator or EmailSecurityPipelineOrchestrator()

    async def analyze_email(
        self,
        raw_email: RawEmail,
        context: PipelineContext | None = None,
        cancellation_token: asyncio.Event | None = None,
    ) -> EmailAnalysisResult:
        """Analyze raw email end-to-end across Modules 5-11."""
        ctx = context or PipelineContext(tenant_id=raw_email.tenant_id)

        raw_email_id = getattr(raw_email, "raw_email_id", raw_email.id)

        # Emit PipelineStartedEvent
        await self._publish_event(
            PipelineStartedEvent(
                tenant_id=raw_email.tenant_id,
                raw_email_id=raw_email_id,
                message_id=raw_email.message_id or "unknown",
            )
        )

        try:
            result = await self.orchestrator.execute_pipeline(
                raw_email=raw_email, context=ctx, cancellation_token=cancellation_token
            )

            # Emit PipelineCompletedEvent
            await self._publish_event(
                PipelineCompletedEvent(
                    tenant_id=result.tenant_id,
                    analysis_id=result.analysis_id,
                    message_id=result.message_id,
                    verdict=result.risk_assessment.verdict.value,
                    risk_score=result.risk_assessment.risk_score,
                    total_time_ms=result.total_execution_time_ms,
                    sla_breached=result.sla_breached,
                )
            )

            logger.info(
                "End-to-end email analysis completed for msg '%s': verdict=%s, score=%d/100, SLA_breached=%s in %.2fms",
                result.message_id,
                result.risk_assessment.verdict.value,
                result.risk_assessment.risk_score,
                result.sla_breached,
                result.total_execution_time_ms,
            )
            return result
        except Exception as exc:
            # Emit PipelineFailedEvent
            await self._publish_event(
                PipelineFailedEvent(
                    tenant_id=raw_email.tenant_id,
                    raw_email_id=raw_email_id,
                    message_id=raw_email.message_id or "unknown",
                    failed_stage="pipeline_execution",
                    error_message=str(exc),
                )
            )
            logger.error(
                "End-to-end email analysis failed for msg '%s': %s",
                raw_email.message_id,
                exc,
            )
            raise

    async def _publish_event(self, event: BaseEvent) -> None:
        """Safely publish event if event publisher is configured."""
        if self.event_publisher:
            try:
                await self.event_publisher.publish(event)
            except Exception as exc:
                logger.error(
                    "Failed to publish orchestrator event '%s': %s",
                    event.event_type,
                    exc,
                )
