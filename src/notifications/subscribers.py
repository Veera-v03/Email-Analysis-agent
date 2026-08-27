"""EventBus subscribers translating domain security events into multi-channel notifications."""

from __future__ import annotations

from typing import Any

from src.config.logging import get_logger
from src.events.security_events import (
    AnalyticsAggregatedEvent,
    NotificationDispatchedEvent,
    NotificationFailedEvent,
    RemediationExecutedEvent,
    RemediationPendingApprovalEvent,
    RiskScoredEvent,
)
from src.interfaces.event_publisher import IEventPublisher
from src.interfaces.event_subscriber import IEventSubscriber
from src.notifications.engine import NotificationEngine
from src.notifications.models import NotificationPayloadDTO, NotificationPriority

logger = get_logger("scamon.notifications.subscribers")


class NotificationEventSubscriber:
    """Subscribes to security domain events and dispatches notifications via NotificationEngine."""

    def __init__(
        self,
        engine: NotificationEngine,
        publisher: IEventPublisher | None = None,
    ) -> None:
        self.engine = engine
        self.publisher = publisher

    def subscribe_to_bus(self, subscriber: IEventSubscriber) -> None:
        """Register event listeners on the event bus."""
        subscriber.subscribe(RemediationExecutedEvent, self.handle_remediation_executed)
        subscriber.subscribe(RemediationPendingApprovalEvent, self.handle_remediation_pending_approval)
        subscriber.subscribe(RiskScoredEvent, self.handle_risk_scored)
        subscriber.subscribe(AnalyticsAggregatedEvent, self.handle_analytics_aggregated)
        logger.info("NotificationEventSubscriber registered event listeners.")

    async def _post_dispatch_publish(
        self,
        payload: NotificationPayloadDTO,
        summary: Any,
    ) -> None:
        """Publish NotificationDispatchedEvent or NotificationFailedEvent to EventBus if publisher configured."""
        if not self.publisher:
            return

        try:
            from uuid import UUID, uuid4

            tenant_uuid = uuid4()
            if isinstance(payload.tenant_id, str):
                try:
                    tenant_uuid = UUID(payload.tenant_id)
                except ValueError:
                    tenant_uuid = uuid4()

            if summary.delivered_channels:
                await self.publisher.publish(
                    NotificationDispatchedEvent(
                        tenant_id=tenant_uuid,
                        notification_id=str(payload.notification_id),
                        event_name=payload.event_name,
                        delivered_channels=[ch.value for ch in summary.delivered_channels],
                        duration_ms=summary.total_duration_ms,
                    )
                )
            if summary.failed_channels:
                error_msgs = [
                    f"{ch.value}: {summary.channel_results.get(ch.value, {}).error or 'failed'}"
                    for ch in summary.failed_channels
                ]
                await self.publisher.publish(
                    NotificationFailedEvent(
                        tenant_id=tenant_uuid,
                        notification_id=str(payload.notification_id),
                        event_name=payload.event_name,
                        failed_channels=[ch.value for ch in summary.failed_channels],
                        error_summary="; ".join(error_msgs),
                    )
                )
        except Exception as exc:
            logger.warning("Failed to publish notification event to EventBus: %s", exc)

    async def handle_remediation_executed(self, event: RemediationExecutedEvent) -> None:
        """Handle remediation execution outcome."""
        priority = NotificationPriority.HIGH if event.status == "SUCCESS" else NotificationPriority.CRITICAL
        tenant_id = getattr(event, "tenant_id", "default_org")
        payload = NotificationPayloadDTO(
            tenant_id=str(tenant_id),
            event_name=event.event_type,
            title=f"Remediation Executed: {event.action_taken.value.upper()}",
            message=(
                f"Security remediation action '{event.action_taken.value}' was executed "
                f"by adapter '{event.adapter_name}' with status '{event.status}'."
            ),
            priority=priority,
            message_id=event.message_id,
            metadata={
                "action": event.action_taken.value,
                "adapter": event.adapter_name,
                "status": event.status,
                "ref_id": event.external_reference_id or "none",
            },
        )
        summary = await self.engine.dispatch(payload)
        await self._post_dispatch_publish(payload, summary)

    async def handle_remediation_pending_approval(
        self, event: RemediationPendingApprovalEvent
    ) -> None:
        """Handle remediation requiring human SOC analyst approval."""
        tenant_id = getattr(event, "tenant_id", "default_org")
        payload = NotificationPayloadDTO(
            tenant_id=str(tenant_id),
            event_name=event.event_type,
            title=f"Action Approval Required: {event.requested_action.value.upper()}",
            message=(
                f"High-impact remediation action '{event.requested_action.value}' "
                f"requires authorization. Reason: {event.reason}"
            ),
            priority=NotificationPriority.CRITICAL,
            message_id=event.message_id,
            metadata={
                "requested_action": event.requested_action.value,
                "reason": event.reason,
            },
        )
        summary = await self.engine.dispatch(payload)
        await self._post_dispatch_publish(payload, summary)

    async def handle_risk_scored(self, event: RiskScoredEvent) -> None:
        """Handle risk scoring verdict for high/critical threats."""
        # Only notify for malicious or suspicious verdicts to avoid alert fatigue
        if event.verdict.value not in ("MALICIOUS", "SUSPICIOUS"):
            return

        priority = (
            NotificationPriority.CRITICAL
            if event.verdict.value == "MALICIOUS"
            else NotificationPriority.MEDIUM
        )
        tenant_id = getattr(event, "tenant_id", "default_org")
        payload = NotificationPayloadDTO(
            tenant_id=str(tenant_id),
            event_name=event.event_type,
            title=f"Security Threat Detected: {event.verdict.value.upper()} (Risk: {event.risk_score}/100)",
            message=(
                f"Risk assessment flagged email as '{event.verdict.value}'. "
                f"Recommended action: '{event.recommended_action.value}'. "
                f"Explanation: {event.explainability_summary}"
            ),
            priority=priority,
            incident_id=str(event.incident_id),
            message_id=event.message_id,
            metadata={
                "verdict": event.verdict.value,
                "risk_score": event.risk_score,
                "categories": event.threat_categories,
                "recommended_action": event.recommended_action.value,
            },
        )
        summary = await self.engine.dispatch(payload)
        await self._post_dispatch_publish(payload, summary)

    async def handle_analytics_aggregated(self, event: AnalyticsAggregatedEvent) -> None:
        """Handle periodic analytics aggregation summary."""
        tenant_id = getattr(event, "tenant_id", "default_org")
        payload = NotificationPayloadDTO(
            tenant_id=str(tenant_id),
            event_name=event.event_type,
            title=f"Daily Threat Analytics Summary ({event.time_window_hours}h Window)",
            message=(
                f"Analytics summary: {event.total_emails_analyzed} emails analyzed, "
                f"{event.total_threats_detected} threats identified, "
                f"{event.remediations_executed} remediations executed."
            ),
            priority=NotificationPriority.INFO,
            metadata={
                "time_window_hours": event.time_window_hours,
                "total_analyzed": event.total_emails_analyzed,
                "total_threats": event.total_threats_detected,
                "remediations": event.remediations_executed,
            },
        )
        summary = await self.engine.dispatch(payload)
        await self._post_dispatch_publish(payload, summary)
