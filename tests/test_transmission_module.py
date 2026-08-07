"""Comprehensive unit and integration test suite for Module 7 Header & Transmission Analysis Engine."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from uuid import uuid4

from src.container.di import Container
from src.events.base_event import BaseEvent
from src.events.transmission_events import (
    HeaderAnalysisCompletedEvent,
    HeaderAnomalyDetectedEvent,
)
from src.messaging.event_bus import InMemoryEventBus
from src.parsing.models import HeaderAddressDTO, ParsedEmail, ReceivedHopDTO
from src.registry.module_registry import ModuleRegistry
from src.transmission.engine import TransmissionAnalysisEngine
from src.transmission.identity.spoofing_detector import detect_display_name_spoofing
from src.transmission.module import TransmissionModule, register_transmission_module
from src.transmission.pipeline import TransmissionAnalysisPipeline


def test_display_name_spoofing_detection() -> None:
    """Verify executive display name spoofing detection."""
    # CEO name paired with free webmail address
    assert detect_display_name_spoofing("CEO Jane Doe", "jane.doe@gmail.com") is True

    # Embedded email in display name != From address
    assert (
        detect_display_name_spoofing("admin@paypal.com Security", "attacker@phish.ru")
        is True
    )

    # Legitimate internal email
    assert detect_display_name_spoofing("Jane Doe", "jane.doe@enterprise.com") is False


def test_transmission_pipeline_analysis() -> None:
    """Verify TransmissionAnalysisPipeline hop reconstruction, BEC detection, and anomaly scoring."""
    parsed = ParsedEmail(
        raw_email_id=uuid4(),
        account_id=uuid4(),
        tenant_id=uuid4(),
        message_id="msg_007",
        internet_message_id="<msg_007@phish.com>",
        sender=HeaderAddressDTO(name="CEO John Smith", address="john.smith@gmail.com"),
        reply_to=HeaderAddressDTO(name="Attacker", address="harvest@evil-phish.ru"),
        recipients_to=[
            HeaderAddressDTO(name="Victim", address="victim@enterprise.com")
        ],
        subject="Re: Urgent Wire Transfer Request",
        date=datetime.now(UTC),
        received_hops=[
            ReceivedHopDTO(
                hop_index=0,
                from_server="mail.phish.com",
                by_server="mx.enterprise.com",
                client_ip="203.0.113.195",
                timestamp=datetime.now(UTC),
            )
        ],
        raw_headers={
            "return-path": ["<bounce@evil-phish.ru>"],
        },
    )

    pipeline = TransmissionAnalysisPipeline()
    analysis = pipeline.analyze(parsed)

    # 1. Primary Identifiers
    assert analysis.message_id == "msg_007"
    assert analysis.sender_identity.from_address == "john.smith@gmail.com"

    # 2. Security Flags
    assert analysis.sender_identity.is_display_name_spoofed is True
    assert analysis.sender_identity.is_reply_to_mismatched is True
    assert analysis.sender_identity.is_return_path_mismatched is True
    assert analysis.is_thread_hijack_suspect is True

    # 3. Anomalies
    codes = [a.anomaly_code for a in analysis.anomalies]
    assert "ANOM_DISPLAY_NAME_SPOOFING" in codes
    assert "ANOM_REPLY_TO_MISMATCH" in codes
    assert "ANOM_THREAD_HIJACK_SUSPECT" in codes
    assert analysis.header_integrity_score < 0.5


def test_transmission_engine_events() -> None:
    """Verify TransmissionAnalysisEngine event emission to EventBus."""

    async def _run() -> None:
        published: list[BaseEvent] = []

        class MockPublisher:
            async def publish(self, event: BaseEvent) -> None:
                published.append(event)

        engine = TransmissionAnalysisEngine(event_publisher=MockPublisher())

        parsed = ParsedEmail(
            raw_email_id=uuid4(),
            account_id=uuid4(),
            tenant_id=uuid4(),
            message_id="msg_evt_777",
            internet_message_id="<evt777@company.com>",
            sender=HeaderAddressDTO(name="CFO Alex", address="alex@yahoo.com"),
            reply_to=HeaderAddressDTO(name="Alex", address="alex.cfo@yahoo.com"),
            recipients_to=[HeaderAddressDTO(name="User", address="user@company.com")],
            subject="Invoice Payment",
            date=datetime.now(UTC),
        )

        analysis = await engine.analyze_transmission(parsed)
        assert analysis.sender_identity.is_display_name_spoofed is True

        completed_events = [
            e for e in published if isinstance(e, HeaderAnalysisCompletedEvent)
        ]
        anomaly_events = [
            e for e in published if isinstance(e, HeaderAnomalyDetectedEvent)
        ]

        assert len(completed_events) == 1
        assert completed_events[0].is_display_name_spoofed is True
        assert len(anomaly_events) >= 1

    asyncio.run(_run())


def test_transmission_module_lifecycle() -> None:
    """Verify TransmissionModule DI container registration and health check lifecycle."""

    async def _run() -> None:
        di = Container()
        registry = ModuleRegistry()
        bus = InMemoryEventBus()

        mod = register_transmission_module(di, registry, event_publisher=bus)
        assert registry.get_module("transmission") == mod

        await registry.initialize_all()

        health = await registry.health_check_all()
        assert health.status == "UP"

        await registry.shutdown_all()

    asyncio.run(_run())
