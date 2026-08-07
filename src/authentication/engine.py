"""Central AuthenticationVerificationEngine for email authentication verification and event publishing."""

from __future__ import annotations

from src.authentication.models import AuthenticationVerification
from src.authentication.pipeline import AuthenticationPipeline
from src.config.logging import get_logger
from src.events.base_event import BaseEvent
from src.events.security_events import AuthEvaluatedEvent
from src.interfaces.event_publisher import IEventPublisher
from src.parsing.models import ParsedEmail
from src.transmission.models import TransmissionAnalysis

logger = get_logger("scamon.authentication.engine")


class AuthenticationVerificationEngine:
    """Central engine executing authentication verification and publishing AuthEvaluatedEvent."""

    def __init__(self, event_publisher: IEventPublisher | None = None) -> None:
        self.event_publisher = event_publisher
        self.pipeline = AuthenticationPipeline()

    async def verify_authentication(
        self, parsed: ParsedEmail, transmission: TransmissionAnalysis
    ) -> AuthenticationVerification:
        """Verify SPF, DKIM, DMARC, ARC authentication and publish AuthEvaluatedEvent."""
        verification = self.pipeline.verify(parsed, transmission)

        # Emit AuthEvaluatedEvent (Reused security event contract)
        await self._publish_event(
            AuthEvaluatedEvent(
                tenant_id=verification.tenant_id,
                message_id=verification.message_id,
                spf_result=verification.spf.result,
                dkim_result=verification.dkim_overall_result,
                dmarc_result=verification.dmarc.result,
                arc_chain_valid=verification.arc.chain_valid,
            )
        )

        logger.info(
            "Authentication verification completed for msg '%s': DMARC=%s, SPF=%s, DKIM=%s in %.2fms",
            verification.message_id,
            verification.dmarc.result,
            verification.spf.result,
            verification.dkim_overall_result,
            verification.verification_time_ms,
        )
        return verification

    async def _publish_event(self, event: BaseEvent) -> None:
        """Safely publish event if event publisher is configured."""
        if self.event_publisher:
            try:
                await self.event_publisher.publish(event)
            except Exception as exc:
                logger.error(
                    "Failed to publish authentication event '%s': %s",
                    event.event_type,
                    exc,
                )
