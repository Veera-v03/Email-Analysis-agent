"""Event contracts and payload schemas for ScamON Enterprise."""

from __future__ import annotations

from src.events.audit_events import (
    ActionExecutedEvent,
    PolicyTriggeredEvent,
    SecurityAuditEvent,
)
from src.events.base_event import BaseEvent
from src.events.email_events import (
    EmailIngestedEvent,
    EmailRenderedEvent,
)
from src.events.email_events import (
    EmailParsedEvent as LegacyEmailParsedEvent,
)
from src.events.iam_events import (
    PermissionDeniedEvent,
    TokenRefreshedEvent,
    UserLoggedInEvent,
    UserLoggedOutEvent,
    UserLoginFailedEvent,
)
from src.events.ingestion_events import (
    EmailDownloadedEvent,
    EmailReceivedEvent,
    MailboxSyncCompletedEvent,
    MailboxSyncFailedEvent,
)
from src.events.parsing_events import (
    AttachmentExtractedEvent,
    EmailParsedEvent,
    EmailParsingFailedEvent,
)
from src.events.security_events import (
    AuthEvaluatedEvent,
    IntelEnrichedEvent,
    RiskScoredEvent,
)
from src.events.system_events import (
    ComponentDegradedEvent,
    SystemShutdownEvent,
    SystemStartedEvent,
)

__all__ = [
    "ActionExecutedEvent",
    "AttachmentExtractedEvent",
    "AuthEvaluatedEvent",
    "BaseEvent",
    "ComponentDegradedEvent",
    "EmailDownloadedEvent",
    "EmailIngestedEvent",
    "EmailParsedEvent",
    "EmailParsingFailedEvent",
    "EmailRenderedEvent",
    "IntelEnrichedEvent",
    "LegacyEmailParsedEvent",
    "MailboxSyncCompletedEvent",
    "MailboxSyncFailedEvent",
    "PermissionDeniedEvent",
    "PolicyTriggeredEvent",
    "RiskScoredEvent",
    "SecurityAuditEvent",
    "SystemShutdownEvent",
    "SystemStartedEvent",
    "TokenRefreshedEvent",
    "UserLoggedInEvent",
    "UserLoggedOutEvent",
    "UserLoginFailedEvent",
]
