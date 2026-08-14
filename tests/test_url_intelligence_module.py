"""Comprehensive unit and integration test suite for Module 15 URL & Sandbox Intelligence Engine."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from uuid import uuid4

from src.container.di import Container
from src.content_intelligence.models import MediaStatus
from src.database.models import RawEmail
from src.orchestrator.engine import OrchestratorEngine
from src.parsing.models import HeaderAddressDTO, ParsedEmail
from src.parsing.url.url_extractor import (
    extract_urls_from_html,
    normalize_url_canonical,
)
from src.registry.module_registry import ModuleRegistry
from src.risk.registry import RiskFeatureRegistry
from src.threat_intel.providers.google_safe_browsing import GoogleSafeBrowsingProvider
from src.threat_intel.providers.openphish import OpenPhishProvider
from src.threat_intel.providers.phishtank import PhishTankProvider
from src.url_intelligence.engine import URLIntelligenceEngine
from src.url_intelligence.module import URLIntelligenceModule, register_url_module
from src.url_intelligence.pipeline import URLIntelligencePipeline
from src.url_intelligence.redirect_expander import RedirectExpander
from src.url_intelligence.sandbox_engine import PlaywrightSandboxEngine
from src.url_intelligence.ssrf_validator import SSRFValidator


def test_url_canonicalization() -> None:
    """Verify normalize_url_canonical strips default ports and normalizes scheme/domain."""
    assert (
        normalize_url_canonical("HTTP://EXAMPLE.COM:80/path/")
        == "http://example.com/path/"
    )
    assert (
        normalize_url_canonical("HTTPS://Sub.Domain.com:443/test")
        == "https://sub.domain.com/test"
    )
    assert normalize_url_canonical("https://domain.com.") == "https://domain.com"


def test_ssrf_validator_prohibited_ips() -> None:
    """Verify SSRFValidator blocks loopback, private IPv4/v6, cloud metadata, and IPv4-mapped IPv6."""
    validator = SSRFValidator()

    # Prohibited IPs
    assert validator.is_ip_prohibited("127.0.0.1") is True
    assert validator.is_ip_prohibited("10.0.0.5") is True
    assert validator.is_ip_prohibited("192.168.1.100") is True
    assert validator.is_ip_prohibited("172.16.0.1") is True
    assert validator.is_ip_prohibited("169.254.169.254") is True
    assert validator.is_ip_prohibited("::1") is True
    assert validator.is_ip_prohibited("::ffff:127.0.0.1") is True
    assert validator.is_ip_prohibited("fe80::1") is True

    # Safe Public IPs
    assert validator.is_ip_prohibited("8.8.8.8") is False
    assert validator.is_ip_prohibited("93.184.216.34") is False

    # Prohibited Hostnames
    safe, _ = validator.validate_url("http://localhost/admin")
    assert safe is False
    safe_meta, _ = validator.validate_url("http://169.254.169.254/latest/meta-data")
    assert safe_meta is False


def test_redirect_expander_per_hop_ssrf_and_loop_detection() -> None:
    """Verify RedirectExpander expands redirect chains up to 5 hops with per-hop SSRF validation and loop detection."""
    expander = RedirectExpander()

    # Shortened URL expansion
    chain = expander.expand_url("http://bit.ly/3AbCd12")
    assert chain.total_hops == 2
    assert chain.final_destination_url == "https://phishing-portal.com/login"
    assert chain.is_shortener_expanded is True

    # Redirect loop detection
    chain_loop = expander.expand_url("http://loop.com/redirect")
    assert chain_loop.is_loop_detected is True

    # SSRF blocked target
    chain_ssrf = expander.expand_url("http://127.0.0.1/internal")
    assert chain_ssrf.hops[0].is_ssrf_safe is False


def test_playwright_sandbox_engine_policy_and_dto() -> None:
    """Verify PlaywrightSandboxEngine enforces trigger policy and returns metadata DTO with screenshot reference."""
    sandbox = PlaywrightSandboxEngine(force_allow_mock=True)

    # Triggered sandbox execution
    res = sandbox.run_sandbox("https://fakebank-login.com/secure", is_shortened=True)
    assert res.sandbox_status == MediaStatus.SUCCESS
    assert res.has_credential_inputs is True
    assert res.screenshot_available is True
    assert res.screenshot_reference is not None

    # Skipped execution for non-triggered safe URL
    res_skipped = sandbox.run_sandbox("https://google.com/about")
    assert res_skipped.sandbox_status == MediaStatus.SKIPPED


def test_url_threat_providers() -> None:
    """Verify GoogleSafeBrowsingProvider, PhishTankProvider, and OpenPhishProvider lookup behavior."""
    gsb = GoogleSafeBrowsingProvider()
    pt = PhishTankProvider()
    op = OpenPhishProvider()

    from src.security_intelligence.threat_intel.framework import ThreatIntelTargetType

    obs_gsb = gsb.lookup(
        "http://phishing-portal.com/login", target_type=ThreatIntelTargetType.URL
    )  # URL target
    assert obs_gsb is not None
    assert obs_gsb.malicious is True
    assert obs_gsb.provider_name == "Google Safe Browsing"

    obs_pt = pt.lookup(
        "http://phishing-portal.com/login", target_type=ThreatIntelTargetType.URL
    )
    assert obs_pt is not None
    assert obs_pt.malicious is True
    assert obs_pt.provider_name == "PhishTank"

    obs_op = op.lookup(
        "http://phishing-portal.com/login", target_type=ThreatIntelTargetType.URL
    )
    assert obs_op is not None
    assert obs_op.malicious is True
    assert obs_op.provider_name == "OpenPhish"


def test_url_feature_extractor_module10_integration() -> None:
    """Verify URLFeatureExtractor maps URL intelligence features into Module 10 RiskFeatureRegistry."""
    registry = RiskFeatureRegistry()
    extractor = [
        p for p in registry._providers.values() if p.provider_name == "url_intelligence"
    ][0]

    parsed = ParsedEmail(
        raw_email_id=uuid4(),
        account_id=uuid4(),
        tenant_id=uuid4(),
        message_id="msg_url_feat",
        internet_message_id="<url_feat@test.com>",
        sender=HeaderAddressDTO(name="Sender", address="sender@test.com"),
        date=datetime.now(UTC),
        urls=extract_urls_from_html(
            "<a href='http://bit.ly/3AbCd12'>https://google.com</a>"
        ),
    )

    features = extractor.extract_features(parsed=parsed)

    assert features["has_mismatched_urls"] is True
    assert features["has_shortened_urls"] is True
    assert features["extracted_urls_count"] == 1


def test_module15_orchestrator_stage36_integration() -> None:
    """Verify Module 12 Pipeline Orchestrator executes Stage 3.6 URL Intelligence cleanly."""

    async def _run() -> None:
        engine = OrchestratorEngine()

        raw_email = RawEmail(
            id=uuid4(),
            account_id=uuid4(),
            tenant_id=uuid4(),
            message_id="msg_stage36_test",
            internet_message_id="<stage36@company.com>",
            raw_eml_data=b"From: User <user@company.com>\r\nTo: rcpt@company.com\r\nSubject: Test\r\n\r\nLink: http://bit.ly/3AbCd12",
        )

        result = await engine.analyze_email(raw_email)

        assert result.analysis_id is not None
        assert "url_intelligence" in result.sla_metrics
        assert result.risk_assessment is not None
        assert result.decision_plan is not None

    asyncio.run(_run())


def test_url_intelligence_module_lifecycle() -> None:
    """Verify URLIntelligenceModule DI container registration and health check lifecycle."""

    async def _run() -> None:
        di = Container()
        registry = ModuleRegistry()

        mod = register_url_module(di, registry)
        assert registry.get_module("url_intelligence") == mod

        await registry.initialize_all()

        health = await registry.health_check_all()
        assert health.status == "UP"

        await registry.shutdown_all()

    asyncio.run(_run())
