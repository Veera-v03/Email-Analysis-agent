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
    EmailParsedEvent,
    EmailRenderedEvent,
)
from src.events.iam_events import (
    PermissionDeniedEvent,
    TokenRefreshedEvent,
    UserLoggedInEvent,
    UserLoggedOutEvent,
    UserLoginFailedEvent,
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
    "AuthEvaluatedEvent",
    "BaseEvent",
    "ComponentDegradedEvent",
    "EmailIngestedEvent",
    "EmailParsedEvent",
    "EmailRenderedEvent",
    "IntelEnrichedEvent",
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
