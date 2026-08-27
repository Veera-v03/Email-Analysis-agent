"""Comprehensive unit and integration tests for Module 20 Enterprise SOC Alerting Engine."""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from src.common.constants import ActionTaken, Verdict
from src.container.di import Container
from src.events.security_events import (
    AnalyticsAggregatedEvent,
    NotificationDispatchedEvent,
    NotificationFailedEvent,
    RemediationExecutedEvent,
    RemediationPendingApprovalEvent,
    RiskScoredEvent,
)
from src.messaging.event_bus import InMemoryEventBus
from src.notifications.channels.email import EmailAsyncChannel
from src.notifications.channels.slack import SlackAsyncChannel
from src.notifications.channels.teams import TeamsAsyncChannel
from src.notifications.channels.webhook import (
    WebhookAsyncChannel,
    compute_hmac_signature,
    validate_webhook_url_ssrf,
)
from src.notifications.engine import NotificationEngine
from src.notifications.exceptions import SSRFSecurityError
from src.notifications.models import (
    ChannelDeliveryResultDTO,
    ChannelType,
    DeliveryStatus,
    NotificationPayloadDTO,
    NotificationPriority,
    TenantNotificationConfigDTO,
)
from src.notifications.module import NotificationModule, register_notification_module
from src.notifications.notifier import NotificationDispatcher, NotificationEvent
from src.notifications.sanitizer import (
    sanitize_metadata,
    sanitize_payload,
    sanitize_text,
)
from src.notifications.subscribers import NotificationEventSubscriber
from src.registry.module_registry import ModuleRegistry
from src.remediation.models import RemediationResultDTO
from src.remediation.siem_exporter import SIEMIntegrationEngine


# ===========================================================================
# 1. PII and Secret Sanitization Tests
# ===========================================================================
def test_sanitizer_redacts_sensitive_strings() -> None:
    text = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9 and password: mySuperSecret123 with api_key=sk-12345678901234567890"
    sanitized = sanitize_text(text)
    assert "[REDACTED]" in sanitized
    assert "mySuperSecret123" not in sanitized
    assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in sanitized


def test_sanitizer_redacts_metadata_dictionary() -> None:
    meta = {
        "tenant_id": "org_1",
        "password": "secret_password",
        "raw_body": "This is raw email body text with secrets",
        "client_secret": "xyz123",
        "safe_key": "safe_value",
        "nested": {
            "token": "secret_token_abc",
            "info": "clean",
        },
    }
    cleaned = sanitize_metadata(meta)
    assert cleaned["password"] == "[REDACTED]"
    assert cleaned["raw_body"] == "[REDACTED]"
    assert cleaned["client_secret"] == "[REDACTED]"
    assert cleaned["safe_key"] == "safe_value"
    assert cleaned["nested"]["token"] == "[REDACTED]"
    assert cleaned["nested"]["info"] == "clean"


def test_sanitizer_payload_dto() -> None:
    payload = NotificationPayloadDTO(
        tenant_id="tenant_100",
        event_name="test_event",
        title="Alert with password=supersecret",
        message="Message contains Bearer abcd1234efgh5678ijkl",
        priority=NotificationPriority.HIGH,
        metadata={"api_key": "secret_key_123"},
    )
    sanitized = sanitize_payload(payload)
    assert "supersecret" not in sanitized.title
    assert "abcd1234efgh5678ijkl" not in sanitized.message
    assert sanitized.metadata["api_key"] == "[REDACTED]"


# ===========================================================================
# 2. SSRF Protection and URL Validation Tests
# ===========================================================================
def test_ssrf_rejects_unsupported_schemes() -> None:
    with pytest.raises(SSRFSecurityError, match="Unsupported URL scheme"):
        validate_webhook_url_ssrf("ftp://example.com/webhook")

    with pytest.raises(SSRFSecurityError, match="Unsupported URL scheme"):
        validate_webhook_url_ssrf("file:///etc/passwd")


def test_ssrf_rejects_localhost_and_blocked_hostnames() -> None:
    with pytest.raises(SSRFSecurityError, match="Blocked hostname"):
        validate_webhook_url_ssrf("http://localhost/webhook")

    with pytest.raises(SSRFSecurityError, match="Blocked hostname"):
        validate_webhook_url_ssrf("http://metadata.google.internal/computeMetadata")


def test_ssrf_rejects_private_and_loopback_ips() -> None:
    with patch("socket.getaddrinfo", return_value=[(None, None, None, None, ("127.0.0.1", 80))]):
        with pytest.raises(SSRFSecurityError, match="restricted network"):
            validate_webhook_url_ssrf("http://internal.service.com/webhook")

    with patch("socket.getaddrinfo", return_value=[(None, None, None, None, ("10.0.1.5", 80))]):
        with pytest.raises(SSRFSecurityError, match="restricted network"):
            validate_webhook_url_ssrf("http://internal.corp/webhook")

    with patch("socket.getaddrinfo", return_value=[(None, None, None, None, ("169.254.169.254", 80))]):
        with pytest.raises(SSRFSecurityError, match="restricted network"):
            validate_webhook_url_ssrf("http://cloud.metadata/webhook")


def test_ssrf_allows_public_ips() -> None:
    with patch("socket.getaddrinfo", return_value=[(None, None, None, None, ("93.184.216.34", 443))]):
        # Should not raise
        validate_webhook_url_ssrf("https://api.external-webhook.com/soc/alerts")


# ===========================================================================
# 3. HMAC-SHA256 Webhook Signing Tests
# ===========================================================================
def test_hmac_signature_calculation() -> None:
    secret = "my_webhook_secret_key"
    payload_json = '{"event":"test","status":"ok"}'
    ts = "1724745600"

    sig1 = compute_hmac_signature(payload_json, secret, ts)
    sig2 = compute_hmac_signature(payload_json, secret, ts)
    assert sig1 == sig2
    assert len(sig1) == 64  # SHA256 hex digest length

    # Changed timestamp produces different signature
    sig3 = compute_hmac_signature(payload_json, secret, "1724745601")
    assert sig1 != sig3


# ===========================================================================
# 4. Individual Channel Dispatch Tests (Mocked Network)
# ===========================================================================
@pytest.mark.asyncio
async def test_slack_channel_success() -> None:
    channel = SlackAsyncChannel(default_webhook_url="https://hooks.slack.com/services/T00/B00/X00")
    payload = NotificationPayloadDTO(
        tenant_id="org_1",
        event_name="remediation_executed",
        title="Quarantine Executed",
        message="Mailbox message was quarantined.",
        priority=NotificationPriority.HIGH,
        incident_id="inc_123",
        message_id="msg_456",
    )

    mock_resp = MagicMock()
    mock_resp.is_success = True
    mock_resp.status_code = 200

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_resp) as mock_post:
        result = await channel.send_async(payload)
        assert result.status == DeliveryStatus.DELIVERED
        assert result.status_code == 200
        mock_post.assert_called_once()


@pytest.mark.asyncio
async def test_slack_channel_failure_handling() -> None:
    channel = SlackAsyncChannel(default_webhook_url="https://hooks.slack.com/services/T00/B00/X00")
    payload = NotificationPayloadDTO(
        tenant_id="org_1",
        event_name="remediation_executed",
        title="Test Alert",
        message="Test Message",
    )

    mock_resp = MagicMock()
    mock_resp.is_success = False
    mock_resp.status_code = 500
    mock_resp.text = "Internal Server Error"

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_resp):
        result = await channel.send_async(payload)
        assert result.status == DeliveryStatus.FAILED
        assert result.status_code == 500
        assert "Slack HTTP error 500" in (result.error or "")


@pytest.mark.asyncio
async def test_teams_channel_success() -> None:
    channel = TeamsAsyncChannel(default_webhook_url="https://outlook.office.com/webhook/xxx")
    payload = NotificationPayloadDTO(
        tenant_id="org_2",
        event_name="threat_detected",
        title="Phishing Threat Flagged",
        message="High-confidence phishing campaign detected.",
        priority=NotificationPriority.CRITICAL,
    )

    mock_resp = MagicMock()
    mock_resp.is_success = True
    mock_resp.status_code = 200

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_resp):
        result = await channel.send_async(payload)
        assert result.status == DeliveryStatus.DELIVERED
        assert result.status_code == 200


@pytest.mark.asyncio
async def test_webhook_channel_with_hmac_and_ssrf_success() -> None:
    channel = WebhookAsyncChannel(
        default_webhook_url="https://api.partner.com/soc/webhook",
        signing_secret="super_secret_signing_key",
        enforce_ssrf_check=True,
    )
    payload = NotificationPayloadDTO(
        tenant_id="org_partner",
        event_name="remediation_executed",
        title="Account Locked",
        message="Okta identity suspended.",
        priority=NotificationPriority.HIGH,
    )

    mock_resp = MagicMock()
    mock_resp.is_success = True
    mock_resp.status_code = 202

    with patch("socket.getaddrinfo", return_value=[(None, None, None, None, ("93.184.216.34", 443))]), \
         patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_resp) as mock_post:
        result = await channel.send_async(payload)
        assert result.status == DeliveryStatus.DELIVERED
        assert result.status_code == 202

        # Verify HMAC signature header was attached
        call_kwargs = mock_post.call_args[1]
        headers = call_kwargs["headers"]
        assert "X-ScamON-Signature" in headers
        assert headers["X-ScamON-Signature"].startswith("sha256=")
        assert "X-ScamON-Timestamp" in headers


@pytest.mark.asyncio
async def test_webhook_channel_ssrf_blocks_private_ip() -> None:
    channel = WebhookAsyncChannel(
        default_webhook_url="http://192.168.1.50/internal/webhook",
        enforce_ssrf_check=True,
    )
    payload = NotificationPayloadDTO(
        tenant_id="org_test",
        event_name="test",
        title="Test",
        message="Test",
    )

    with patch("socket.getaddrinfo", return_value=[(None, None, None, None, ("192.168.1.50", 80))]):
        result = await channel.send_async(payload)
        assert result.status == DeliveryStatus.FAILED
        assert "SSRF Security Violation" in (result.error or "")


@pytest.mark.asyncio
async def test_email_channel_simulated_and_smtp() -> None:
    # 1. Simulated default delivery
    email_channel = EmailAsyncChannel(default_recipients=["soc@company.com"])
    payload = NotificationPayloadDTO(
        tenant_id="org_1",
        event_name="alert",
        title="Email Alert Title",
        message="Email Alert Body",
        priority=NotificationPriority.INFO,
    )

    res = await email_channel.send_async(payload)
    assert res.status == DeliveryStatus.DELIVERED
    assert res.status_code == 250

    # 2. SMTP Host delivery in thread
    smtp_channel = EmailAsyncChannel(
        default_recipients=["soc@company.com"],
        smtp_host="smtp.company.internal",
    )
    with patch("smtplib.SMTP") as mock_smtp_cls:
        mock_instance = MagicMock()
        mock_smtp_cls.return_value.__enter__.return_value = mock_instance

        res_smtp = await smtp_channel.send_async(payload)
        assert res_smtp.status == DeliveryStatus.DELIVERED
        mock_instance.send_message.assert_called_once()


# ===========================================================================
# 5. NotificationEngine Coordination, Retries, Rate-Limiting & Dedup Tests
# ===========================================================================
@pytest.mark.asyncio
async def test_engine_dispatch_all_channels() -> None:
    engine = NotificationEngine()

    mock_slack = AsyncMock(return_value=ChannelDeliveryResultDTO(status=DeliveryStatus.DELIVERED, channel=ChannelType.SLACK))
    mock_teams = AsyncMock(return_value=ChannelDeliveryResultDTO(status=DeliveryStatus.DELIVERED, channel=ChannelType.TEAMS))
    mock_webhook = AsyncMock(return_value=ChannelDeliveryResultDTO(status=DeliveryStatus.DELIVERED, channel=ChannelType.WEBHOOK))
    mock_email = AsyncMock(return_value=ChannelDeliveryResultDTO(status=DeliveryStatus.DELIVERED, channel=ChannelType.EMAIL))

    engine.register_channel(MagicMock(channel_type=ChannelType.SLACK, send_async=mock_slack))
    engine.register_channel(MagicMock(channel_type=ChannelType.TEAMS, send_async=mock_teams))
    engine.register_channel(MagicMock(channel_type=ChannelType.WEBHOOK, send_async=mock_webhook))
    engine.register_channel(MagicMock(channel_type=ChannelType.EMAIL, send_async=mock_email))

    payload = NotificationPayloadDTO(
        tenant_id="tenant_alpha",
        event_name="incident_alert",
        title="Multi-Channel Security Alert",
        message="Testing parallel dispatch.",
        priority=NotificationPriority.HIGH,
    )

    summary = await engine.dispatch(payload)
    assert len(summary.delivered_channels) == 4
    assert len(summary.failed_channels) == 0
    assert summary.is_suppressed is False
    assert summary.total_duration_ms >= 0.0


@pytest.mark.asyncio
async def test_engine_retry_exponential_backoff() -> None:
    engine = NotificationEngine(max_retries=2, retry_backoff_sec=0.01)

    fail_then_succeed = AsyncMock(
        side_effect=[
            ChannelDeliveryResultDTO(status=DeliveryStatus.FAILED, error="Network glitch", channel=ChannelType.SLACK),
            ChannelDeliveryResultDTO(status=DeliveryStatus.DELIVERED, channel=ChannelType.SLACK),
        ]
    )
    engine.register_channel(MagicMock(channel_type=ChannelType.SLACK, send_async=fail_then_succeed))

    payload = NotificationPayloadDTO(
        tenant_id="tenant_retry",
        event_name="retry_test",
        title="Retry Test",
        message="Retry message",
    )

    summary = await engine.dispatch(payload, channels=[ChannelType.SLACK])
    assert ChannelType.SLACK in summary.delivered_channels
    assert fail_then_succeed.call_count == 2


@pytest.mark.asyncio
async def test_engine_rate_limiting_per_tenant() -> None:
    engine = NotificationEngine(default_rate_limit=2)

    mock_email = AsyncMock(return_value=ChannelDeliveryResultDTO(status=DeliveryStatus.DELIVERED, channel=ChannelType.EMAIL))
    engine.register_channel(MagicMock(channel_type=ChannelType.EMAIL, send_async=mock_email))

    payload = NotificationPayloadDTO(
        tenant_id="tenant_flood",
        event_name="event_flood",
        title="Flood Alert",
        message="Msg",
    )

    # First 2 allowed
    s1 = await engine.dispatch(payload, channels=[ChannelType.EMAIL])
    assert ChannelType.EMAIL in s1.delivered_channels

    s2 = await engine.dispatch(payload, channels=[ChannelType.EMAIL])
    assert ChannelType.EMAIL in s2.delivered_channels

    # 3rd is rate limited
    s3 = await engine.dispatch(payload, channels=[ChannelType.EMAIL])
    assert len(s3.delivered_channels) == 0
    assert s3.channel_results[ChannelType.EMAIL.value].status == DeliveryStatus.RATE_LIMITED


@pytest.mark.asyncio
async def test_engine_duplicate_threat_suppression() -> None:
    engine = NotificationEngine()
    mock_slack = AsyncMock(return_value=ChannelDeliveryResultDTO(status=DeliveryStatus.DELIVERED, channel=ChannelType.SLACK))
    engine.register_channel(MagicMock(channel_type=ChannelType.SLACK, send_async=mock_slack))

    config = TenantNotificationConfigDTO(
        tenant_id="tenant_dedup",
        threat_dedup_window_sec=60,
    )
    engine.set_tenant_config(config)

    payload1 = NotificationPayloadDTO(
        tenant_id="tenant_dedup",
        event_name="malicious_threat_flagged",
        title="Threat Alert",
        message="Duplicate threat body",
        incident_id="inc_duplicate_99",
    )
    payload2 = NotificationPayloadDTO(
        tenant_id="tenant_dedup",
        event_name="malicious_threat_flagged",
        title="Threat Alert",
        message="Duplicate threat body",
        incident_id="inc_duplicate_99",
    )

    s1 = await engine.dispatch(payload1, channels=[ChannelType.SLACK])
    assert s1.is_suppressed is False
    assert ChannelType.SLACK in s1.delivered_channels

    s2 = await engine.dispatch(payload2, channels=[ChannelType.SLACK])
    assert s2.is_suppressed is True


# ===========================================================================
# 6. EventBus Subscription and Event Publishing Tests
# ===========================================================================
@pytest.mark.asyncio
async def test_event_bus_subscriber_workflow() -> None:
    bus = InMemoryEventBus()
    await bus.initialize()

    engine = NotificationEngine()
    mock_dispatch = AsyncMock(
        return_value=MagicMock(
            delivered_channels=[ChannelType.SLACK],
            failed_channels=[],
            total_duration_ms=10.5,
            channel_results={},
        )
    )
    engine.dispatch = mock_dispatch  # type: ignore

    subscriber = NotificationEventSubscriber(engine=engine, publisher=bus)
    subscriber.subscribe_to_bus(bus)

    published_events: list[Any] = []

    async def _capture_dispatched(evt: NotificationDispatchedEvent) -> None:
        published_events.append(evt)

    bus.subscribe(NotificationDispatchedEvent, _capture_dispatched)

    # 1. Trigger RemediationExecutedEvent
    remediation_evt = RemediationExecutedEvent(
        tenant_id=uuid4(),
        message_id="<msg_test_1@domain.com>",
        action_taken=ActionTaken.QUARANTINED,
        adapter_name="MicrosoftGraphAdapter",
        external_reference_id="ref_msft_123",
        status="SUCCESS",
    )
    await bus.publish(remediation_evt)
    await asyncio.sleep(0.05)

    assert mock_dispatch.call_count == 1
    assert len(published_events) == 1
    assert published_events[0].event_name == "scamon.prod.remediation.executed.v1"
    assert "slack" in published_events[0].delivered_channels

    # 2. Trigger RiskScoredEvent (Malicious)
    risk_evt = RiskScoredEvent(
        tenant_id=uuid4(),
        incident_id=uuid4(),
        message_id="<msg_test_2@domain.com>",
        risk_score=92,
        verdict=Verdict.MALICIOUS,
        threat_categories=["credential_harvesting", "brand_spoofing"],
        recommended_action=ActionTaken.BLOCKED,
        explainability_summary="Spoofed sender and high-entropy malicious link.",
    )
    await bus.publish(risk_evt)
    await asyncio.sleep(0.05)

    assert mock_dispatch.call_count == 2

    # 3. Trigger AnalyticsAggregatedEvent
    analytics_evt = AnalyticsAggregatedEvent(
        tenant_id=uuid4(),
        time_window_hours=24,
        total_emails_analyzed=150,
        total_threats_detected=12,
        remediations_executed=8,
    )
    await bus.publish(analytics_evt)
    await asyncio.sleep(0.05)

    assert mock_dispatch.call_count == 3
    await bus.shutdown()


# ===========================================================================
# 7. NotificationModule Lifecycle & DI Registration Tests
# ===========================================================================
@pytest.mark.asyncio
async def test_notification_module_lifecycle_and_di() -> None:
    container = Container()
    registry = ModuleRegistry()

    mod = register_notification_module(container, registry)
    assert mod.name == "notifications"
    assert mod.version == "1.0.0"

    await registry.initialize_all()
    health = await mod.health_check()
    assert health.status == "HEALTHY"
    assert health.details["initialized"] is True
    assert "dispatched_count" in health.details

    await registry.shutdown_all()
    assert mod._is_initialized is False


# ===========================================================================
# 8. Backward Compatibility with Legacy Notifier & SIEM Integration Tests
# ===========================================================================
def test_legacy_notifier_backward_compatibility() -> None:
    dispatcher = NotificationDispatcher()
    evt = NotificationEvent(
        event_name="legacy_test",
        title="Legacy Alert",
        message="Legacy message format",
        severity="high",
        metadata={"tenant_id": "legacy_org"},
    )
    # Synchronous call must execute cleanly without exception
    dispatcher.dispatch(evt)


def test_siem_exporter_backward_compatibility() -> None:
    from src.remediation.models import ActionStatus

    siem = SIEMIntegrationEngine()
    result_dto = RemediationResultDTO(
        remediation_id=uuid4(),
        tenant_id=uuid4(),
        incident_id=uuid4(),
        message_id="<msg_siem@enterprise.com>",
        assessment_id=uuid4(),
        decision_plan_id=uuid4(),
        requested_action=ActionTaken.QUARANTINED,
        approved_action=ActionTaken.QUARANTINED,
        action_status=ActionStatus.VERIFIED,
        idempotency_key="idemp_key_siem_123",
        executing_adapter="MicrosoftGraphAdapter",
        external_reference_id="ref_ms_123",
        execution_time_ms=45.2,
    )

    status = siem.export_siem_event(result_dto)
    assert status == "SIEM_EXPORTED"
