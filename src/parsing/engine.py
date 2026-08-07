"""Central MimeParserEngine for raw EML parsing and event publishing."""

from __future__ import annotations

from uuid import UUID

from src.config.logging import get_logger
from src.events.base_event import BaseEvent
from src.events.parsing_events import AttachmentExtractedEvent, EmailParsedEvent
from src.interfaces.event_publisher import IEventPublisher
from src.parsing.models import ParsedEmail
from src.parsing.pipeline import ParsingPipeline

logger = get_logger("scamon.parsing.engine")


class MimeParserEngine:
    """Central engine for executing MIME parsing pipeline and publishing parsing events."""

    def __init__(self, event_publisher: IEventPublisher | None = None) -> None:
        self.event_publisher = event_publisher
        self.pipeline = ParsingPipeline()

    async def parse_email(
        self,
        raw_eml_bytes: bytes,
        raw_email_id: UUID,
        account_id: UUID,
        tenant_id: UUID,
        message_id: str,
        internet_message_id: str,
    ) -> ParsedEmail:
        """Parse raw EML bytes into ParsedEmail and publish EmailParsedEvent."""
        parsed = self.pipeline.parse(
            raw_eml_bytes=raw_eml_bytes,
            raw_email_id=raw_email_id,
            account_id=account_id,
            tenant_id=tenant_id,
            message_id=message_id,
            internet_message_id=internet_message_id,
        )

        total_recipients = (
            len(parsed.recipients_to)
            + len(parsed.recipients_cc)
            + len(parsed.recipients_bcc)
        )
        total_atts = len(parsed.attachments) + len(parsed.inline_images)

        # Emit EmailParsedEvent
        await self._publish_event(
            EmailParsedEvent(
                tenant_id=tenant_id,
                parsed_id=parsed.parsed_id,
                raw_email_id=raw_email_id,
                account_id=account_id,
                message_id=message_id,
                internet_message_id=internet_message_id,
                sender_address=parsed.sender.address,
                recipient_count=total_recipients,
                attachment_count=total_atts,
                url_count=len(parsed.urls),
                parsing_time_ms=parsed.parsing_time_ms,
            )
        )

        # Emit AttachmentExtractedEvent for every attachment
        for att in parsed.attachments + parsed.inline_images:
            await self._publish_event(
                AttachmentExtractedEvent(
                    tenant_id=tenant_id,
                    attachment_id=att.attachment_id,
                    parsed_id=parsed.parsed_id,
                    filename=att.filename,
                    detected_mime_type=att.detected_mime_type,
                    size_bytes=att.size_bytes,
                    sha256=att.sha256,
                    is_inline=att.is_inline,
                )
            )

        logger.info(
            "Parsed email '%s' for tenant '%s' in %.2fms (%d atts, %d urls)",
            message_id,
            tenant_id,
            parsed.parsing_time_ms,
            total_atts,
            len(parsed.urls),
        )
        return parsed

    async def _publish_event(self, event: BaseEvent) -> None:
        """Safely publish event if event publisher is configured."""
        if self.event_publisher:
            try:
                await self.event_publisher.publish(event)
            except Exception as exc:
                logger.error(
                    "Failed to publish parsing event '%s': %s", event.event_type, exc
                )
