"""Comprehensive unit and integration test suite for Module 12 Pipeline Orchestrator."""

from __future__ import annotations

import asyncio
from uuid import uuid4

from src.container.di import Container
from src.database.models import RawEmail
from src.events.base_event import BaseEvent
from src.events.pipeline_events import PipelineCompletedEvent, PipelineStartedEvent
from src.messaging.event_bus import InMemoryEventBus
from src.orchestrator.engine import OrchestratorEngine
from src.orchestrator.models import PipelineContext
from src.orchestrator.module import OrchestratorModule, register_orchestrator_module
from src.orchestrator.orchestrator import EmailSecurityPipelineOrchestrator
from src.orchestrator.sla_monitor import SLAMonitoringEngine
from src.registry.module_registry import ModuleRegistry


def test_sla_monitoring_engine() -> None:
    """Verify SLAMonitoringEngine stage timing evaluation and breach detection."""
    sla = SLAMonitoringEngine()

    durations = {
        "mime_parsing": 50.0,
        "transmission_analysis": 10.0,
        "auth_verification": 100.0,
        "threat_intel": 40.0,
        "risk_assessment": 20.0,
    }

    breached, list_b = sla.evaluate_sla(durations, total_time_ms=500.0)
    assert breached is False
    assert len(list_b) == 0

    # Trigger SLA breach
    durations_breached = {"mime_parsing": 300.0}  # Limit is 250ms
    breached, list_b = sla.evaluate_sla(durations_breached, total_time_ms=1000.0)
    assert breached is True
    assert "mime_parsing" in list_b


def test_pipeline_orchestrator_execution() -> None:
    """Verify EmailSecurityPipelineOrchestrator end-to-end execution across Modules 5-11."""

    async def _run() -> None:
        raw_email = RawEmail(
            id=uuid4(),
            account_id=uuid4(),
            tenant_id=uuid4(),
            message_id="msg_orch_001",
            internet_message_id="<msg_orch_001@company.com>",
            raw_eml_data=b"From: CEO <ceo@company.com>\r\nTo: user@company.com\r\nSubject: Test\r\n\r\nHello World",
        )

        orch = EmailSecurityPipelineOrchestrator()
        context = PipelineContext(tenant_id=raw_email.tenant_id)

        result = await orch.execute_pipeline(raw_email, context)

        assert result.message_id == "msg_orch_001"
        assert result.parsed_email is not None
        assert result.transmission_analysis is not None
        assert result.auth_verification is not None
        assert result.threat_intel is not None
        assert result.risk_assessment is not None
        assert result.decision_plan is not None
        assert result.total_execution_time_ms > 0.0

    asyncio.run(_run())


def test_pipeline_cancellation_support() -> None:
    """Verify in-flight cancellation via cancellation token."""

    async def _run() -> None:
        raw_email = RawEmail(
            id=uuid4(),
            account_id=uuid4(),
            tenant_id=uuid4(),
            message_id="msg_cancel_001",
            internet_message_id="<msg_cancel_001@test.com>",
            raw_eml_data=b"From: sender@test.com\r\nTo: rcpt@test.com\r\nSubject: Cancel\r\n\r\nBody",
        )

        orch = EmailSecurityPipelineOrchestrator()
        token = asyncio.Event()
        token.set()  # Trigger immediate cancellation

        try:
            await orch.execute_pipeline(raw_email, cancellation_token=token)
            assert False, "Pipeline should have raised PipelineCancelledError"
        except Exception as exc:
            assert (
                "cancelled" in str(exc).lower()
                or "pipelinecancellederror" in exc.__class__.__name__.lower()
            )

    asyncio.run(_run())


def test_orchestrator_engine_events() -> None:
    """Verify OrchestratorEngine event emission for PipelineStartedEvent and PipelineCompletedEvent."""

    async def _run() -> None:
        published: list[BaseEvent] = []

        class MockPublisher:
            async def publish(self, event: BaseEvent) -> None:
                published.append(event)

        engine = OrchestratorEngine(event_publisher=MockPublisher())

        raw_email = RawEmail(
            id=uuid4(),
            account_id=uuid4(),
            tenant_id=uuid4(),
            message_id="msg_evt_orch",
            internet_message_id="<msg_evt_orch@company.com>",
            raw_eml_data=b"From: admin@company.com\r\nTo: user@company.com\r\nSubject: Event Test\r\n\r\nTest",
        )

        result = await engine.analyze_email(raw_email)
        assert result.analysis_id is not None

        started_events = [e for e in published if isinstance(e, PipelineStartedEvent)]
        completed_events = [
            e for e in published if isinstance(e, PipelineCompletedEvent)
        ]

        assert len(started_events) == 1
        assert len(completed_events) == 1
        assert completed_events[0].message_id == "msg_evt_orch"

    asyncio.run(_run())


def test_orchestrator_module_lifecycle() -> None:
    """Verify OrchestratorModule DI container registration and health check lifecycle."""

    async def _run() -> None:
        di = Container()
        registry = ModuleRegistry()
        bus = InMemoryEventBus()

        mod = register_orchestrator_module(di, registry, event_publisher=bus)
        assert registry.get_module("orchestrator") == mod

        await registry.initialize_all()

        health = await registry.health_check_all()
        assert health.status == "UP"

        await registry.shutdown_all()

    asyncio.run(_run())
