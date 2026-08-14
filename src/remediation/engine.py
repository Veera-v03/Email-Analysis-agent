"""Central RemediationEngine entry point for Module 17."""

from __future__ import annotations

from uuid import UUID

from src.ai_decision.models import DecisionPlan
from src.common.constants import ActionTaken
from src.config.logging import get_logger
from src.events.security_events import (
    RemediationExecutedEvent,
    RemediationPendingApprovalEvent,
)
from src.interfaces.event_publisher import IEventPublisher
from src.remediation.dispatcher import RemediationDispatcher
from src.remediation.models import (
    ActionStatus,
    HumanApprovalTokenDTO,
    RemediationResultDTO,
)
from src.risk.models import RiskAssessment

logger = get_logger("scamon.remediation.engine")


class RemediationEngine:
    """Central engine entry point executing remediation, policy checks, and event publication."""

    def __init__(
        self,
        event_publisher: IEventPublisher | None = None,
        dispatcher: RemediationDispatcher | None = None,
    ) -> None:
        self.event_publisher = event_publisher
        self.dispatcher = dispatcher or RemediationDispatcher()

    async def execute_remediation(
        self,
        tenant_id: UUID,
        incident_id: UUID,
        assessment: RiskAssessment,
        decision_plan: DecisionPlan,
        requested_action: ActionTaken,
        target_id: str = "default_recipient",
        approval_token: HumanApprovalTokenDTO | None = None,
        is_dry_run: bool = False,
    ) -> RemediationResultDTO:
        """Execute complete remediation workflow and publish resulting events."""
        result = self.dispatcher.dispatch_remediation(
            tenant_id=tenant_id,
            incident_id=incident_id,
            assessment=assessment,
            decision_plan=decision_plan,
            requested_action=requested_action,
            target_id=target_id,
            approval_token=approval_token,
            is_dry_run=is_dry_run,
        )

        if self.event_publisher:
            try:
                if result.action_status == ActionStatus.PENDING_APPROVAL:
                    await self.event_publisher.publish(
                        RemediationPendingApprovalEvent(
                            tenant_id=result.tenant_id,
                            message_id=result.message_id,
                            requested_action=result.requested_action,
                            reason="High-impact action requires human authorization",
                        )
                    )
                else:
                    await self.event_publisher.publish(
                        RemediationExecutedEvent(
                            tenant_id=result.tenant_id,
                            message_id=result.message_id,
                            action_taken=result.approved_action,
                            adapter_name=result.executing_adapter,
                            external_reference_id=result.external_reference_id,
                            status=str(result.action_status),
                        )
                    )
            except Exception as exc:
                logger.debug("Event publishing for remediation failed: %s", exc)

        logger.info(
            "Remediation finished for msg '%s': status=%s, action=%s, adapter=%s in %.2fms",
            result.message_id,
            result.action_status,
            result.approved_action,
            result.executing_adapter,
            result.execution_time_ms,
        )
        return result
