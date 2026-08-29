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
from src.events.feedback_events import (
    AnalystVerdictSubmittedEvent,
    FalseNegativeConfirmedEvent,
    FalsePositiveConfirmedEvent,
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
from src.events.pipeline_events import (
    PipelineCompletedEvent,
    PipelineFailedEvent,
    PipelineStartedEvent,
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
from src.events.transmission_events import (
    HeaderAnalysisCompletedEvent,
    HeaderAnomalyDetectedEvent,
)

__all__ = [
    "ActionExecutedEvent",
    "AnalystVerdictSubmittedEvent",
    "AttachmentExtractedEvent",
    "AuthEvaluatedEvent",
    "BaseEvent",
    "ComponentDegradedEvent",
    "EmailDownloadedEvent",
    "EmailIngestedEvent",
    "EmailParsedEvent",
    "EmailParsingFailedEvent",
    "EmailReceivedEvent",
    "EmailRenderedEvent",
    "FalseNegativeConfirmedEvent",
    "FalsePositiveConfirmedEvent",
    "HeaderAnalysisCompletedEvent",
    "HeaderAnomalyDetectedEvent",
    "IntelEnrichedEvent",
    "LegacyEmailParsedEvent",
    "MailboxSyncCompletedEvent",
    "MailboxSyncFailedEvent",
    "PermissionDeniedEvent",
    "PipelineCompletedEvent",
    "PipelineFailedEvent",
    "PipelineStartedEvent",
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
