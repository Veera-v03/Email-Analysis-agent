"""Comprehensive unit and integration test suite for Module 16 Threat Correlation & Campaign Intelligence Engine."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from uuid import uuid4

from src.container.di import Container
from src.database.db_client import DatabaseClient
from src.database.models import RawEmail
from src.events.security_events import ThreatCorrelatedEvent
from src.messaging.event_bus import InMemoryEventBus
from src.orchestrator.engine import OrchestratorEngine
from src.parsing.models import HeaderAddressDTO, ParsedEmail
from src.parsing.url.url_extractor import parse_url_entity
from src.registry.module_registry import ModuleRegistry
from src.risk.registry import RiskFeatureRegistry
from src.security_intelligence.campaign.campaign_correlation import (
    CampaignCorrelationEngine,
)
from src.security_intelligence.risk.risk_enrichment import RiskEnrichmentService
from src.threat_correlation.engine import ThreatCorrelationEngine
from src.threat_correlation.graph_builder import IOCGraphBuilder
from src.threat_correlation.module import (
    ThreatCorrelationModule,
    register_threat_correlation_module,
)
from src.threat_correlation.pipeline import ThreatCorrelationPipeline


def test_ioc_graph_builder() -> None:
    """Verify IOCGraphBuilder constructs adjacency list graph mapping cross-indicator relationships."""
    builder = IOCGraphBuilder()

    parsed = ParsedEmail(
        raw_email_id=uuid4(),
        account_id=uuid4(),
        tenant_id=uuid4(),
        message_id="msg_graph_test",
        internet_message_id="<graph@company.com>",
        sender=HeaderAddressDTO(name="Attacker", address="attacker@phish.com"),
        date=datetime.now(UTC),
        urls=[parse_url_entity("https://phishing-portal.com/login")],
    )

    graph_dto = builder.build_graph(parsed=parsed)

    assert graph_dto.total_nodes >= 3
    assert "attacker@phish.com" in graph_dto.nodes
    assert "domain:phish.com" in graph_dto.nodes
    assert "url:https://phishing-portal.com/login" in graph_dto.nodes
    assert "domain:phishing-portal.com" in graph_dto.nodes


def test_campaign_correlation_and_tenant_isolation() -> None:
    """Verify CampaignCorrelationEngine correlates incidents with mandatory tenant_id (org_id) isolation."""
    db = DatabaseClient()
    conn = db.get_connection()

    tenant_a = str(uuid4())
    tenant_b = str(uuid4())

    try:
        with conn:
            # Seed tenant A and B organization records
            conn.execute(
                "INSERT OR IGNORE INTO organizations (id, name, created_at) VALUES (?, ?, ?);",
                (tenant_a, f"Org_{tenant_a}", "2026-08-09T00:00:00Z"),
            )
            conn.execute(
                "INSERT OR IGNORE INTO organizations (id, name, created_at) VALUES (?, ?, ?);",
                (tenant_b, f"Org_{tenant_b}", "2026-08-09T00:00:00Z"),
            )

        with conn:
            # Seed past investigation for Tenant A
            conn.execute(
                "INSERT INTO investigations (id, org_id, email_id, subject, sender, verdict, confidence, risk_level, duration_ms, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
                (
                    str(uuid4()),
                    tenant_a,
                    "email_1",
                    "URGENT Payment Request",
                    "phisher@bad.com",
                    "MALICIOUS",
                    0.95,
                    "HIGH",
                    120,
                    "2026-08-09T00:00:00Z",
                ),
            )

        engine = CampaignCorrelationEngine(client=db)

        # Correlation run for Tenant A -> Match expected
        res_a = engine.correlate_investigation(
            org_id=tenant_a,
            sender="phisher@bad.com",
            subject="URGENT Payment Request",
            extracted_iocs={"urls": []},
        )
        assert res_a["campaign_detected"] is True
        assert "sender_match" in res_a["indicators_matched"]

        # Correlation run for Tenant B with identical sender -> ZERO MATCH due to strict tenant isolation
        res_b = engine.correlate_investigation(
            org_id=tenant_b,
            sender="phisher@bad.com",
            subject="URGENT Payment Request",
            extracted_iocs={"urls": []},
        )
        assert res_b["campaign_detected"] is False
        assert len(res_b["correlated_investigations"]) == 0
    finally:
        conn.close()


def test_risk_enrichment_mitre_mapping() -> None:
    """Verify RiskEnrichmentService maps behavioral tactics to MITRE ATT&CK techniques."""
    enrichment = RiskEnrichmentService()

    profile = enrichment.enrich_risk_profile(
        risk_level="HIGH",
        behavioral_results={
            "detected_tactics": ["credential_harvesting", "bec_impersonation"]
        },
    )

    assert "Business Email Compromise (BEC)" in profile["threat_categories"]
    tech_ids = [t["id"] for t in profile["mitre_attack_mapping"]]
    assert "T1566.002" in tech_ids  # Spearphishing Link
    assert "T1566.003" in tech_ids  # Spearphishing Attachment


def test_threat_correlated_event_emission() -> None:
    """Verify ThreatCorrelationEngine emits ThreatCorrelatedEvent to EventBus."""

    async def _run() -> None:
        event_bus = InMemoryEventBus()
        events_captured: list[ThreatCorrelatedEvent] = []

        async def _handler(evt: ThreatCorrelatedEvent) -> None:
            events_captured.append(evt)

        event_bus.subscribe(ThreatCorrelatedEvent, _handler)

        engine = ThreatCorrelationEngine(event_publisher=event_bus)

        parsed = ParsedEmail(
            raw_email_id=uuid4(),
            account_id=uuid4(),
            tenant_id=uuid4(),
            message_id="msg_event_test",
            internet_message_id="<evt@company.com>",
            sender=HeaderAddressDTO(name="Sender", address="sender@company.com"),
            date=datetime.now(UTC),
            subject="Test Subject",
        )

        res = await engine.correlate_threats(parsed)

        assert res.correlation_id is not None
        assert len(events_captured) == 1
        assert events_captured[0].message_id == "msg_event_test"

    asyncio.run(_run())


def test_correlation_feature_extractor_module10_integration() -> None:
    """Verify CorrelationFeatureExtractor maps correlation evidence into Module 10 RiskFeatureRegistry."""
    registry = RiskFeatureRegistry()
    extractor = [
        p
        for p in registry._providers.values()
        if p.provider_name == "threat_correlation"
    ][0]

    parsed = ParsedEmail(
        raw_email_id=uuid4(),
        account_id=uuid4(),
        tenant_id=uuid4(),
        message_id="msg_corr_feat",
        internet_message_id="<corr_feat@test.com>",
        sender=HeaderAddressDTO(name="User", address="user@company.com"),
        date=datetime.now(UTC),
    )

    features = extractor.extract_features(parsed=parsed)

    assert "campaign_detected" in features
    assert "campaign_score" in features
    assert "mitre_technique_count" in features


def test_module16_orchestrator_stage37_integration() -> None:
    """Verify Module 12 Pipeline Orchestrator executes Stage 3.7 Threat Correlation cleanly."""

    async def _run() -> None:
        engine = OrchestratorEngine()

        raw_email = RawEmail(
            id=uuid4(),
            account_id=uuid4(),
            tenant_id=uuid4(),
            message_id="msg_stage37_test",
            internet_message_id="<stage37@company.com>",
            raw_eml_data=b"From: User <user@company.com>\r\nTo: rcpt@company.com\r\nSubject: Test\r\n\r\nBody",
        )

        result = await engine.analyze_email(raw_email)

        assert result.analysis_id is not None
        assert "threat_correlation" in result.sla_metrics
        assert result.risk_assessment is not None
        assert result.decision_plan is not None

    asyncio.run(_run())


def test_threat_correlation_module_lifecycle() -> None:
    """Verify ThreatCorrelationModule DI container registration and health check lifecycle."""

    async def _run() -> None:
        di = Container()
        registry = ModuleRegistry()

        mod = register_threat_correlation_module(di, registry)
        assert registry.get_module("threat_correlation") == mod

        await registry.initialize_all()

        health = await registry.health_check_all()
        assert health.status == "UP"

        await registry.shutdown_all()

    asyncio.run(_run())
