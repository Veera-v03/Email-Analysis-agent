"""Comprehensive unit test suite for ScamON Enterprise Module 2 Messaging & Event Bus."""

from __future__ import annotations

import asyncio
from uuid import uuid4

import pytest

from src.bootstrap import bootstrap_application
from src.common.constants import ActionTaken, Verdict
from src.common.models import ComponentHealthDTO
from src.container.di import Container
from src.events.audit_events import SecurityAuditEvent
from src.events.base_event import BaseEvent
from src.events.email_events import EmailIngestedEvent, EmailParsedEvent
from src.events.security_events import RiskScoredEvent
from src.interfaces.event_handler import IEventHandler
from src.interfaces.event_publisher import IEventPublisher
from src.interfaces.event_subscriber import IEventSubscriber
from src.messaging.event_bus import InMemoryEventBus, register_event_bus
from src.messaging.exceptions import EventDispatchError, MessagingError
from src.registry.module_registry import ModuleRegistry


class SampleHandler(IEventHandler[EmailIngestedEvent]):
    """Sample typed handler implementation."""

    def __init__(self) -> None:
        self.handled_events: list[EmailIngestedEvent] = []

    async def handle(self, event: EmailIngestedEvent) -> None:
        self.handled_events.append(event)


def test_event_models_instantiation() -> None:
    """Verify event DTO instantiation and metadata capabilities."""
    tenant_id = uuid4()
    event = EmailIngestedEvent(
        tenant_id=tenant_id,
        message_id="msg-001",
        internet_message_id="<msg-001@test.com>",
        ingestion_source="GRAPH_API",
        raw_eml_s3_uri="s3://eml/test.eml",
    )

    assert event.event_type == "scamon.prod.email.ingested.v1"
    assert event.tenant_id == tenant_id
    assert event.message_id == "msg-001"
    assert event.correlation_id is not None

    risk_event = RiskScoredEvent(
        tenant_id=tenant_id,
        incident_id=uuid4(),
        message_id="msg-001",
        risk_score=95,
        verdict=Verdict.MALICIOUS,
        threat_categories=["BEC", "PHISHING"],
        recommended_action=ActionTaken.RETRACTED,
        explainability_summary="High threat risk detected",
    )
    assert risk_event.verdict == Verdict.MALICIOUS
    assert risk_event.risk_score == 95


def test_event_bus_pub_sub_single_subscriber() -> None:
    """Verify single subscriber event publishing and receipt."""

    async def _run() -> None:
        bus = InMemoryEventBus()
        await bus.initialize()

        handler = SampleHandler()
        bus.subscribe(EmailIngestedEvent, handler)

        tenant_id = uuid4()
        event = EmailIngestedEvent(
            tenant_id=tenant_id,
            message_id="msg-002",
            internet_message_id="<msg-002@test.com>",
            ingestion_source="SMTP_MX",
            raw_eml_s3_uri="s3://eml/002.eml",
        )

        await bus.publish(event)
        assert len(handler.handled_events) == 1
        assert handler.handled_events[0].message_id == "msg-002"

        await bus.shutdown()

    asyncio.run(_run())


def test_event_bus_multiple_subscribers() -> None:
    """Verify multiple subscribers receiving the same published event."""

    async def _run() -> None:
        bus = InMemoryEventBus()
        await bus.initialize()

        received_list_1: list[BaseEvent] = []
        received_list_2: list[BaseEvent] = []

        async def sub1(event: EmailParsedEvent) -> None:
            received_list_1.append(event)

        async def sub2(event: EmailParsedEvent) -> None:
            received_list_2.append(event)

        bus.subscribe(EmailParsedEvent, sub1)
        bus.subscribe(EmailParsedEvent, sub2)

        event = EmailParsedEvent(
            tenant_id=uuid4(),
            message_id="msg-003",
            sender_address="attacker@evil.com",
            recipient_addresses=["victim@company.com"],
            subject="Urgent action required",
        )

        await bus.publish(event)

        assert len(received_list_1) == 1
        assert len(received_list_2) == 1
        assert received_list_1[0].message_id == "msg-003"
        assert received_list_2[0].message_id == "msg-003"

        # Unsubscribe sub1
        bus.unsubscribe(EmailParsedEvent, sub1)
        await bus.publish(event)

        assert len(received_list_1) == 1  # unchanged
        assert len(received_list_2) == 2  # updated

        await bus.shutdown()

    asyncio.run(_run())


def test_event_bus_exception_isolation() -> None:
    """Verify that a failing subscriber handler does not stop other subscribers."""

    async def _run() -> None:
        dlq_events: list[tuple[BaseEvent, str, Exception]] = []

        def dead_letter_cb(event: BaseEvent, sub_name: str, err: Exception) -> None:
            dlq_events.append((event, sub_name, err))

        bus = InMemoryEventBus(dead_letter_callback=dead_letter_cb)
        await bus.initialize()

        success_received: list[BaseEvent] = []

        async def failing_sub(event: SecurityAuditEvent) -> None:
            raise ValueError("Subscriber error boom!")

        async def working_sub(event: SecurityAuditEvent) -> None:
            success_received.append(event)

        bus.subscribe(SecurityAuditEvent, failing_sub)
        bus.subscribe(SecurityAuditEvent, working_sub)

        audit_event = SecurityAuditEvent(
            tenant_id=uuid4(),
            action="USER_LOGIN",
            resource="auth_service",
        )

        # Should not raise exception
        await bus.publish(audit_event)

        # Working subscriber completed
        assert len(success_received) == 1

        # Dead letter callback caught the failure
        assert len(dlq_events) == 1
        assert dlq_events[0][1] == "failing_sub"

        await bus.shutdown()

    asyncio.run(_run())


def test_event_bus_health_check() -> None:
    """Verify health check metrics reporting on InMemoryEventBus."""

    async def _run() -> None:
        bus = InMemoryEventBus()
        await bus.initialize()

        async def sub(event: BaseEvent) -> None:
            pass

        bus.subscribe(BaseEvent, sub)

        event = BaseEvent(tenant_id=uuid4(), event_type="test.event")
        await bus.publish(event)

        health: ComponentHealthDTO = await bus.health_check()
        assert health.status == "HEALTHY"
        assert health.details["published_count"] == 1
        assert health.details["dispatched_count"] == 1
        assert health.details["error_count"] == 0

        await bus.shutdown()

    asyncio.run(_run())


def test_register_event_bus_di() -> None:
    """Verify registration of InMemoryEventBus into DI Container and ModuleRegistry."""

    async def _run() -> None:
        di_c = Container()
        reg = ModuleRegistry()

        bus = register_event_bus(di_c, reg)

        assert di_c.has(InMemoryEventBus)
        assert di_c.has(IEventPublisher)
        assert di_c.has(IEventSubscriber)
        assert reg.get_module("event_bus") == bus

        await reg.initialize_all()

        health = await reg.health_check_all()
        assert health.status == "UP"

        await reg.shutdown_all()

    asyncio.run(_run())


def test_messaging_exceptions() -> None:
    """Verify custom exception inheritance in messaging package."""
    err = EventDispatchError("Dispatch failed", details={"handler": "test_handler"})
    assert err.status_code == 500
    assert isinstance(err, MessagingError)
