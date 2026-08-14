"""Unit and integration test suite for Module 19 Threat Analytics & Executive Reporting Engine."""

from __future__ import annotations

import asyncio
from uuid import uuid4

import pytest

from src.analytics.engine import AnalyticsEngine
from src.analytics.exceptions import ReportingError
from src.analytics.models import TenantAnalyticsRequestDTO
from src.analytics.module import register_analytics_module
from src.analytics.report_generator import ExecutiveReportGenerator
from src.container.di import Container
from src.database.db_client import DatabaseClient
from src.events.security_events import AnalyticsAggregatedEvent
from src.registry.module_registry import ModuleRegistry


def test_analytics_engine_aggregation() -> None:
    """Verify AnalyticsEngine trend aggregation over tenant-isolated records."""
    engine = AnalyticsEngine()
    tenant_id = uuid4()

    req = TenantAnalyticsRequestDTO(tenant_id=tenant_id, time_window_hours=24)
    summary = engine.aggregate_tenant_analytics(req)

    assert summary.tenant_id == tenant_id
    assert summary.time_window_hours == 24
    assert summary.total_emails_analyzed >= 0
    assert summary.total_threats_detected >= 0
    assert isinstance(summary.threat_breakdown_by_verdict, dict)
    assert isinstance(summary.remediation_breakdown_by_action, dict)


def test_executive_report_generator() -> None:
    """Verify ExecutiveReportGenerator output in JSON, CSV, and SUMMARY_TEXT formats."""
    engine = AnalyticsEngine()
    tenant_id = uuid4()
    req = TenantAnalyticsRequestDTO(tenant_id=tenant_id, time_window_hours=24)
    summary = engine.aggregate_tenant_analytics(req)

    # 1. JSON Report
    json_report = ExecutiveReportGenerator.generate_report(
        summary, report_format="JSON"
    )
    assert json_report.tenant_id == tenant_id
    assert json_report.report_format == "JSON"
    assert "total_emails_analyzed" in json_report.report_data

    # 2. CSV Report
    csv_report = ExecutiveReportGenerator.generate_report(summary, report_format="CSV")
    assert csv_report.report_format == "CSV"
    assert "Metric Name,Metric Value" in csv_report.report_data

    # 3. Text Summary
    text_report = ExecutiveReportGenerator.generate_report(
        summary, report_format="SUMMARY_TEXT"
    )
    assert text_report.report_format == "SUMMARY_TEXT"
    assert "EXECUTIVE SECURITY POSTURE REPORT" in text_report.report_data

    # 4. Invalid Format
    with pytest.raises(ReportingError):
        ExecutiveReportGenerator.generate_report(summary, report_format="INVALID_FMT")


def test_analytics_aggregated_event() -> None:
    """Verify AnalyticsAggregatedEvent instantiation and field validation."""
    tenant_id = uuid4()
    evt = AnalyticsAggregatedEvent(
        tenant_id=tenant_id,
        time_window_hours=24,
        total_emails_analyzed=10,
        total_threats_detected=2,
        remediations_executed=1,
    )

    assert evt.event_type == "scamon.prod.analytics.aggregated.v1"
    assert evt.tenant_id == tenant_id
    assert evt.total_emails_analyzed == 10


def test_analytics_module_lifecycle() -> None:
    """Verify AnalyticsModule DI container registration and health check lifecycle."""

    async def _run() -> None:
        container = Container()
        registry = ModuleRegistry()

        mod = register_analytics_module(container, registry)
        assert registry.get_module("analytics") == mod

        await registry.initialize_all()
        health = await registry.health_check_all()
        assert health.status == "UP"

        await registry.shutdown_all()

    asyncio.run(_run())
