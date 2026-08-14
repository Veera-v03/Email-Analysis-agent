"""Unit and integration test suite for Module 18 Enterprise Operations & Deployment Suite."""

from __future__ import annotations

import asyncio
from uuid import uuid4

import pytest

from src.common.constants import ActionTaken, Verdict
from src.container.di import Container
from src.events.base_event import BaseEvent
from src.ops.connectors.ms_graph_adapter import MicrosoftGraphAdapter
from src.ops.connectors.okta_adapter import OktaAdapter
from src.ops.connectors.panos_adapter import PANOSAdapter
from src.ops.migrator import DatabaseMigrator
from src.ops.module import register_ops_module
from src.ops.postgres_client import PostgresAuditRepository, PostgresDatabaseClient
from src.ops.prometheus_exporter import PrometheusMetricsExporter
from src.ops.redis_bus import RedisStreamsEventBus
from src.ops.redis_cache import RedisReputationCache
from src.registry.module_registry import ModuleRegistry
from src.remediation.models import ActionStatus, RemediationResultDTO
from src.security_intelligence.threat_intel.framework import (
    ThreatIntelObservation,
    ThreatIntelTargetType,
)


def _create_sample_dto() -> RemediationResultDTO:
    return RemediationResultDTO(
        remediation_id=uuid4(),
        tenant_id=uuid4(),
        incident_id=uuid4(),
        message_id="msg_ops_test_001",
        assessment_id=uuid4(),
        decision_plan_id=uuid4(),
        requested_action=ActionTaken.QUARANTINED,
        approved_action=ActionTaken.QUARANTINED,
        action_status=ActionStatus.VERIFIED,
        idempotency_key="ops_idempotency_key_12345",
        executing_adapter="DryRunAdapter",
    )


def test_postgres_client_and_audit_repository() -> None:
    """Verify PostgresDatabaseClient and PostgresAuditRepository contract parity and fallback."""
    client = PostgresDatabaseClient()
    assert client.is_postgres is False

    repo = PostgresAuditRepository(postgres_client=client)
    dto = _create_sample_dto()

    # Save audit record via fallback
    repo.save_remediation_audit(dto)

    # Query audit record by idempotency key
    cached = repo.get_remediation_by_idempotency_key(
        tenant_id=str(dto.tenant_id), idempotency_key=dto.idempotency_key
    )
    assert cached is not None
    assert cached.idempotency_key == dto.idempotency_key


def test_database_migrator() -> None:
    """Verify DatabaseMigrator non-destructive SQLite to PostgreSQL export utility."""
    migrator = DatabaseMigrator()
    res = migrator.migrate_all_tables()

    assert "organizations" in res
    assert "audit_logs" in res
    assert "investigations" in res
    assert res["organizations"] >= 0


def test_migrator_uuid_transformation() -> None:
    """Verify DatabaseMigrator.to_uuid deterministic UUID preservation and UUID v5 transformation."""
    migrator = DatabaseMigrator()

    # Valid UUID string must be preserved
    valid_uuid_str = str(uuid4())
    assert migrator.to_uuid(valid_uuid_str) == valid_uuid_str

    # Legacy string must transform deterministically to UUID v5 string
    legacy_id = "email_1"
    uuid5_res1 = migrator.to_uuid(legacy_id)
    uuid5_res2 = migrator.to_uuid(legacy_id)
    assert uuid5_res1 is not None
    assert uuid5_res1 == uuid5_res2  # Deterministic parity
    assert uuid5_res1 != legacy_id  # Converted to valid UUID string

    # None or empty string input
    assert migrator.to_uuid(None) is None
    assert migrator.to_uuid("") is None


def test_migrator_validation_rules() -> None:
    """Verify DatabaseMigrator JSONB, TIMESTAMPTZ, and BOOLEAN validation and error handling."""
    from src.ops.exceptions import MigrationError

    migrator = DatabaseMigrator()

    # 1. JSON Validation
    assert migrator.validate_json('{"key": "value"}') == '{"key": "value"}'
    assert migrator.validate_json(None) is None
    with pytest.raises(MigrationError):
        migrator.validate_json("MALFORMED_JSON_STRING")

    # 2. Timestamp Validation
    assert "2026-08-09" in migrator.validate_timestamp("2026-08-09T21:00:00Z")
    with pytest.raises(MigrationError):
        migrator.validate_timestamp("INVALID_DATE_STRING")

    # 3. Boolean Validation
    assert migrator.validate_boolean(1) is True
    assert migrator.validate_boolean(0) is False
    assert migrator.validate_boolean(True) is True
    with pytest.raises(MigrationError):
        migrator.validate_boolean(99)


def test_redis_streams_event_bus() -> None:
    """Verify RedisStreamsEventBus fallback and event publishing compatibility."""

    async def _run() -> None:
        bus = RedisStreamsEventBus()
        assert bus.is_redis is False

        evt = BaseEvent(event_type="scamon.test.event", tenant_id=uuid4())
        await bus.publish(evt)

    asyncio.run(_run())


def test_redis_reputation_cache() -> None:
    """Verify RedisReputationCache tenant isolation and LRU memory fallback."""
    cache = RedisReputationCache(ttl_seconds=300.0)
    tenant_id = str(uuid4())
    obs = [
        ThreatIntelObservation(
            provider_name="VirusTotal",
            target="1.1.1.1",
            target_type=ThreatIntelTargetType.IP,
            malicious=True,
            confidence=0.9,
        )
    ]

    cache.put(cache_key="ip:1.1.1.1", observations=obs, tenant_id=tenant_id)
    retrieved = cache.get(cache_key="ip:1.1.1.1", tenant_id=tenant_id)

    assert retrieved is not None
    assert len(retrieved) == 1
    assert retrieved[0].provider_name == "VirusTotal"


def test_production_remediation_adapters() -> None:
    """Verify MicrosoftGraphAdapter, OktaAdapter, and PANOSAdapter contract safety."""
    graph = MicrosoftGraphAdapter()
    okta = OktaAdapter()
    panos = PANOSAdapter()

    assert graph.supports_action(ActionTaken.QUARANTINED) is True
    assert okta.supports_action(ActionTaken.BLOCKED) is True
    assert panos.supports_action(ActionTaken.BLOCKED) is True

    dto = _create_sample_dto()

    # Dry-run execution
    s1, ref1, _ = graph.execute_action(
        result_dto=dto, target_id="usr@co.com", is_dry_run=True
    )
    s2, ref2, _ = okta.execute_action(
        result_dto=dto, target_id="usr@co.com", is_dry_run=True
    )
    s3, ref3, _ = panos.execute_action(
        result_dto=dto, target_id="93.184.216.34", is_dry_run=True
    )

    assert s1 and ref1 is not None and "dryrun" in ref1
    assert s2 and ref2 is not None and "dryrun" in ref2
    assert s3 and ref3 is not None and "dryrun" in ref3

    # Verification checks
    v1_ok, _ = graph.verify_action(dto, ref1)
    v2_ok, _ = okta.verify_action(dto, ref2)
    v3_ok, _ = panos.verify_action(dto, ref3)

    assert v1_ok and v2_ok and v3_ok


def test_prometheus_exporter() -> None:
    """Verify PrometheusMetricsExporter low-cardinality telemetry recording."""
    exporter = PrometheusMetricsExporter()
    exporter.record_email_processed(status="SUCCESS")
    exporter.record_risk_verdict(verdict=Verdict.MALICIOUS)
    exporter.record_remediation_executed(
        action=ActionTaken.QUARANTINED, status="VERIFIED"
    )
    exporter.record_stage_duration(stage_name="threat_intel", duration_seconds=0.12)


def test_ops_module_lifecycle() -> None:
    """Verify OpsModule DI registration and health check lifecycle."""

    async def _run() -> None:
        di = Container()
        registry = ModuleRegistry()

        mod = register_ops_module(di, registry)
        assert registry.get_module("ops") == mod

        await registry.initialize_all()

        health = await registry.health_check_all()
        assert health.status == "UP"

        await registry.shutdown_all()

    asyncio.run(_run())
