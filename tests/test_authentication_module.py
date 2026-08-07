"""Comprehensive unit and integration test suite for Module 8 Authentication Verification Engine."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from uuid import uuid4

from src.authentication.crypto.crypto_provider import RSACryptoProvider
from src.authentication.dns.dns_resolver import CachedDNSResolver
from src.authentication.dns.org_domain_resolver import PublicSuffixOrgDomainResolver
from src.authentication.engine import AuthenticationVerificationEngine
from src.authentication.module import (
    AuthenticationModule,
    register_authentication_module,
)
from src.authentication.pipeline import AuthenticationPipeline
from src.container.di import Container
from src.events.base_event import BaseEvent
from src.events.security_events import AuthEvaluatedEvent
from src.messaging.event_bus import InMemoryEventBus
from src.parsing.models import HeaderAddressDTO, ParsedEmail
from src.registry.module_registry import ModuleRegistry
from src.transmission.models import SenderIdentityAnalysisDTO, TransmissionAnalysis


def test_public_suffix_org_domain_resolver() -> None:
    """Verify Public Suffix List organizational domain resolution for DMARC alignment."""
    resolver = PublicSuffixOrgDomainResolver()

    # Subdomains under co.uk
    assert (
        resolver.get_organizational_domain("sub.mail.enterprise.co.uk")
        == "enterprise.co.uk"
    )
    # Multi-level subdomain under .com
    assert resolver.get_organizational_domain("a.b.c.company.com") == "company.com"


def test_cached_dns_resolver_lru_and_ttl() -> None:
    """Verify CachedDNSResolver TTL caching and LRU eviction."""
    dns_res = CachedDNSResolver(positive_ttl_seconds=300.0, max_cache_size=2)

    # 1. Query TXT
    res1 = dns_res.resolve_txt("enterprise.com")
    assert len(res1) > 0

    # 2. Query A record
    res2 = dns_res.resolve_a("localhost")
    assert len(res2) > 0

    # 3. Query another TXT to trigger LRU eviction
    dns_res.resolve_txt("example.org")
    assert len(dns_res._cache) <= 2


def test_rsa_crypto_provider() -> None:
    """Verify RSACryptoProvider signature verification error handling."""
    crypto = RSACryptoProvider()
    # Invalid signature bytes should return False gracefully without crashing
    assert (
        crypto.verify_rsa_signature("dummy_key", b"test data", b"invalid sig") is False
    )


def test_authentication_pipeline_verification() -> None:
    """Verify AuthenticationPipeline SPF, DKIM, DMARC, and ARC evaluation."""
    parsed = ParsedEmail(
        raw_email_id=uuid4(),
        account_id=uuid4(),
        tenant_id=uuid4(),
        message_id="msg_auth_888",
        internet_message_id="<msg888@enterprise.com>",
        sender=HeaderAddressDTO(
            name="Enterprise Admin", address="admin@enterprise.com"
        ),
        subject="Monthly Report",
        date=datetime.now(UTC),
        raw_headers={
            "received-spf": [
                "pass (google.com: domain of admin@enterprise.com designates 192.168.1.10 as permitted sender)"
            ],
            "dkim-signature": [
                "v=1; a=rsa-sha256; d=enterprise.com; s=s1; bh=abc12345; b=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQ=="
            ],
            "arc-seal": [
                "i=1; a=rsa-sha256; cv=pass; d=enterprise.com; s=arc2026; b=sig=="
            ],
        },
    )

    transmission = TransmissionAnalysis(
        parsed_id=parsed.parsed_id,
        raw_email_id=parsed.raw_email_id,
        account_id=parsed.account_id,
        tenant_id=parsed.tenant_id,
        message_id="msg_auth_888",
        internet_message_id="<msg888@enterprise.com>",
        originating_ip="192.168.1.10",
        sender_identity=SenderIdentityAnalysisDTO(
            from_address="admin@enterprise.com",
            from_domain="enterprise.com",
        ),
    )

    pipeline = AuthenticationPipeline()
    verification = pipeline.verify(parsed, transmission)

    assert verification.spf.result == "PASS"
    assert verification.dkim_overall_result == "PASS"
    assert len(verification.dkim_signatures) == 1
    assert verification.dmarc.result == "PASS"
    assert verification.dmarc.spf_aligned is True
    assert verification.dmarc.dkim_aligned is True
    assert verification.arc.chain_valid is True
    assert verification.auth_pass_summary is True
    assert verification.auth_risk_score_impact == 0


def test_authentication_engine_events() -> None:
    """Verify AuthenticationVerificationEngine event emission to EventBus."""

    async def _run() -> None:
        published: list[BaseEvent] = []

        class MockPublisher:
            async def publish(self, event: BaseEvent) -> None:
                published.append(event)

        engine = AuthenticationVerificationEngine(event_publisher=MockPublisher())

        parsed = ParsedEmail(
            raw_email_id=uuid4(),
            account_id=uuid4(),
            tenant_id=uuid4(),
            message_id="msg_evt_auth",
            internet_message_id="<evt_auth@company.com>",
            sender=HeaderAddressDTO(name="User", address="user@company.com"),
            date=datetime.now(UTC),
        )

        transmission = TransmissionAnalysis(
            parsed_id=parsed.parsed_id,
            raw_email_id=parsed.raw_email_id,
            account_id=parsed.account_id,
            tenant_id=parsed.tenant_id,
            message_id="msg_evt_auth",
            internet_message_id="<evt_auth@company.com>",
            originating_ip="10.0.0.5",
            sender_identity=SenderIdentityAnalysisDTO(
                from_address="user@company.com",
                from_domain="company.com",
            ),
        )

        verification = await engine.verify_authentication(parsed, transmission)
        assert verification.auth_pass_summary is True

        auth_events = [e for e in published if isinstance(e, AuthEvaluatedEvent)]
        assert len(auth_events) == 1
        assert auth_events[0].message_id == "msg_evt_auth"
        assert auth_events[0].spf_result == "PASS"

    asyncio.run(_run())


def test_authentication_module_lifecycle() -> None:
    """Verify AuthenticationModule DI container registration and health check lifecycle."""

    async def _run() -> None:
        di = Container()
        registry = ModuleRegistry()
        bus = InMemoryEventBus()

        mod = register_authentication_module(di, registry, event_publisher=bus)
        assert registry.get_module("authentication") == mod

        await registry.initialize_all()

        health = await registry.health_check_all()
        assert health.status == "UP"

        await registry.shutdown_all()

    asyncio.run(_run())
