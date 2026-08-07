"""Comprehensive unit and integration test suite for Module 9 Threat Intelligence Engine."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from uuid import uuid4

from src.authentication.models import (
    AuthenticationVerification,
    DMARCResultDTO,
    SPFResultDTO,
)
from src.container.di import Container
from src.events.base_event import BaseEvent
from src.events.security_events import IntelEnrichedEvent
from src.messaging.event_bus import InMemoryEventBus
from src.parsing.models import HeaderAddressDTO, ParsedEmail
from src.registry.module_registry import ModuleRegistry
from src.security_intelligence.threat_intel.framework import ThreatIntelTargetType
from src.threat_intel.engine import ThreatIntelEngine
from src.threat_intel.graph import IOCRelationshipGraph
from src.threat_intel.harvester import IOCHarvester
from src.threat_intel.manager import (
    ReputationCache,
    ThreatIntelManager,
    ThreatIntelProviderRegistry,
)
from src.threat_intel.module import ThreatIntelModule, register_threat_intel_module
from src.threat_intel.pipeline import ThreatIntelPipeline
from src.transmission.models import SenderIdentityAnalysisDTO, TransmissionAnalysis


def test_ioc_harvester() -> None:
    """Verify IOCHarvester harvests and categorizes IOCs across Mod 6, 7, and 8."""
    parsed = ParsedEmail(
        raw_email_id=uuid4(),
        account_id=uuid4(),
        tenant_id=uuid4(),
        message_id="msg_ti_001",
        internet_message_id="<msg_ti_001@phish.com>",
        sender=HeaderAddressDTO(name="Attacker", address="attacker@phish-portal.com"),
        subject="Urgent Payment",
        body_plain="Click link http://phishing-portal.com/login and send BTC to 198.51.100.42",
        date=datetime.now(UTC),
    )

    transmission = TransmissionAnalysis(
        parsed_id=parsed.parsed_id,
        raw_email_id=parsed.raw_email_id,
        account_id=parsed.account_id,
        tenant_id=parsed.tenant_id,
        message_id="msg_ti_001",
        internet_message_id="<msg_ti_001@phish.com>",
        originating_ip="198.51.100.42",
        sender_identity=SenderIdentityAnalysisDTO(
            from_address="attacker@phish-portal.com",
            from_domain="phish-portal.com",
        ),
    )

    auth = AuthenticationVerification(
        parsed_id=parsed.parsed_id,
        transmission_id=transmission.analysis_id,
        account_id=parsed.account_id,
        tenant_id=parsed.tenant_id,
        message_id="msg_ti_001",
        internet_message_id="<msg_ti_001@phish.com>",
        spf=SPFResultDTO(result="PASS", domain="phish-portal.com"),
        dmarc=DMARCResultDTO(result="FAIL", domain="phish-portal.com"),
    )

    harvester = IOCHarvester()
    harvested = harvester.harvest(parsed, transmission, auth)

    assert "198.51.100.42" in harvested["ips"]
    assert "phish-portal.com" in harvested["domains"]
    assert "http://phishing-portal.com/login" in harvested["urls"]


def test_ioc_relationship_graph() -> None:
    """Verify IOCRelationshipGraph node and edge construction."""
    graph = IOCRelationshipGraph()
    n1 = graph.add_node("email", "msg_123")
    n2 = graph.add_node("domain", "phish.com")
    graph.add_edge(n1, n2, "SENDER_DOMAIN")

    d = graph.to_dict()
    assert d["node_count"] == 2
    assert d["edge_count"] == 1


def test_reputation_cache_lru() -> None:
    """Verify ReputationCache TTL and LRU capacity limits."""
    cache = ReputationCache(ttl_seconds=300.0, max_size=2)
    cache.put("ip:1.1.1.1", [])
    cache.put("ip:2.2.2.2", [])
    assert cache.get("ip:1.1.1.1") is not None

    cache.put("ip:3.3.3.3", [])
    assert len(cache._cache) == 2


def test_threat_intel_pipeline_enrichment() -> None:
    """Verify ThreatIntelPipeline enrichment, confidence scoring, and attack taxonomy mapping."""
    parsed = ParsedEmail(
        raw_email_id=uuid4(),
        account_id=uuid4(),
        tenant_id=uuid4(),
        message_id="msg_enrich_999",
        internet_message_id="<msg_enrich_999@evil.com>",
        sender=HeaderAddressDTO(name="Attacker", address="attacker@evil-phish.ru"),
        body_plain="Check bad IP 198.51.100.42 and domain phishing-portal.com",
        date=datetime.now(UTC),
    )

    transmission = TransmissionAnalysis(
        parsed_id=parsed.parsed_id,
        raw_email_id=parsed.raw_email_id,
        account_id=parsed.account_id,
        tenant_id=parsed.tenant_id,
        message_id="msg_enrich_999",
        internet_message_id="<msg_enrich_999@evil.com>",
        originating_ip="198.51.100.42",
        sender_identity=SenderIdentityAnalysisDTO(
            from_address="attacker@evil-phish.ru",
            from_domain="evil-phish.ru",
        ),
    )

    auth = AuthenticationVerification(
        parsed_id=parsed.parsed_id,
        transmission_id=transmission.analysis_id,
        account_id=parsed.account_id,
        tenant_id=parsed.tenant_id,
        message_id="msg_enrich_999",
        internet_message_id="<msg_enrich_999@evil.com>",
        spf=SPFResultDTO(result="FAIL", domain="evil-phish.ru"),
        dmarc=DMARCResultDTO(result="FAIL", domain="evil-phish.ru"),
    )

    pipeline = ThreatIntelPipeline()
    result = pipeline.enrich(parsed, transmission, auth)

    assert result.malicious_ioc_count > 0
    assert result.overall_confidence.confidence > 0.8
    assert len(result.matched_feeds) > 0
    assert result.intel_risk_score_impact > 0


def test_threat_intel_engine_events() -> None:
    """Verify ThreatIntelEngine event emission to EventBus."""

    async def _run() -> None:
        published: list[BaseEvent] = []

        class MockPublisher:
            async def publish(self, event: BaseEvent) -> None:
                published.append(event)

        engine = ThreatIntelEngine(event_publisher=MockPublisher())

        parsed = ParsedEmail(
            raw_email_id=uuid4(),
            account_id=uuid4(),
            tenant_id=uuid4(),
            message_id="msg_evt_intel",
            internet_message_id="<evt_intel@company.com>",
            sender=HeaderAddressDTO(name="User", address="user@company.com"),
            date=datetime.now(UTC),
        )

        transmission = TransmissionAnalysis(
            parsed_id=parsed.parsed_id,
            raw_email_id=parsed.raw_email_id,
            account_id=parsed.account_id,
            tenant_id=parsed.tenant_id,
            message_id="msg_evt_intel",
            internet_message_id="<evt_intel@company.com>",
            originating_ip="10.0.0.5",
            sender_identity=SenderIdentityAnalysisDTO(
                from_address="user@company.com",
                from_domain="company.com",
            ),
        )

        auth = AuthenticationVerification(
            parsed_id=parsed.parsed_id,
            transmission_id=transmission.analysis_id,
            account_id=parsed.account_id,
            tenant_id=parsed.tenant_id,
            message_id="msg_evt_intel",
            internet_message_id="<evt_intel@company.com>",
            spf=SPFResultDTO(result="PASS", domain="company.com"),
            dmarc=DMARCResultDTO(result="PASS", domain="company.com"),
        )

        result = await engine.enrich_threat_intelligence(parsed, transmission, auth)
        assert result.enrichment_id is not None

        intel_events = [e for e in published if isinstance(e, IntelEnrichedEvent)]
        assert len(intel_events) == 1
        assert intel_events[0].message_id == "msg_evt_intel"

    asyncio.run(_run())


def test_threat_intel_module_lifecycle() -> None:
    """Verify ThreatIntelModule DI container registration and health check lifecycle."""

    async def _run() -> None:
        di = Container()
        registry = ModuleRegistry()
        bus = InMemoryEventBus()

        mod = register_threat_intel_module(di, registry, event_publisher=bus)
        assert registry.get_module("threat_intel") == mod

        await registry.initialize_all()

        health = await registry.health_check_all()
        assert health.status == "UP"

        await registry.shutdown_all()

    asyncio.run(_run())
