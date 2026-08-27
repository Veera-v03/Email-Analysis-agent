"""Module 20 Enterprise SOC Alerting, Multi-Channel Notification & Webhook Dispatch Engine."""

from src.notifications.channels import (
    EmailAsyncChannel,
    IAsyncNotificationChannel,
    SlackAsyncChannel,
    TeamsAsyncChannel,
    WebhookAsyncChannel,
)
from src.notifications.engine import NotificationEngine
from src.notifications.exceptions import (
    ChannelDeliveryError,
    NotificationError,
    PayloadSanitizationError,
    RateLimitExceededError,
    SSRFSecurityError,
)
from src.notifications.models import (
    ChannelDeliveryResultDTO,
    ChannelType,
    DeliveryStatus,
    DispatchSummaryDTO,
    NotificationPayloadDTO,
    NotificationPriority,
    TenantNotificationConfigDTO,
)
from src.notifications.module import (
    NotificationModule,
    register_notification_module,
)
from src.notifications.notifier import (
    EmailNotificationChannel,
    INotificationChannel,
    NotificationDispatcher,
    NotificationEvent,
    SlackNotificationChannel,
    TeamsNotificationChannel,
    WebhookNotificationChannel,
)
from src.notifications.sanitizer import (
    sanitize_metadata,
    sanitize_payload,
    sanitize_text,
)
from src.notifications.subscribers import NotificationEventSubscriber

__all__ = [
    # Modern Module 20 Architecture
    "NotificationEngine",
    "NotificationModule",
    "register_notification_module",
    "NotificationEventSubscriber",
    "IAsyncNotificationChannel",
    "SlackAsyncChannel",
    "TeamsAsyncChannel",
    "WebhookAsyncChannel",
    "EmailAsyncChannel",
    "NotificationPayloadDTO",
    "ChannelDeliveryResultDTO",
    "DispatchSummaryDTO",
    "TenantNotificationConfigDTO",
    "ChannelType",
    "NotificationPriority",
    "DeliveryStatus",
    "NotificationError",
    "ChannelDeliveryError",
    "SSRFSecurityError",
    "RateLimitExceededError",
    "PayloadSanitizationError",
    "sanitize_payload",
    "sanitize_text",
    "sanitize_metadata",
    # Legacy Compatibility Exports
    "NotificationEvent",
    "INotificationChannel",
    "EmailNotificationChannel",
    "WebhookNotificationChannel",
    "SlackNotificationChannel",
    "TeamsNotificationChannel",
    "NotificationDispatcher",
]
