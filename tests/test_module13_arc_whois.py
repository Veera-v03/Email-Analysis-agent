"""Unit and integration tests for Sprint 1.4A - Module 13 Advanced Header & Infrastructure Intelligence."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from uuid import uuid4

from src.authentication.arc.arc_validator import validate_arc_chain
from src.authentication.crypto.crypto_provider import RSACryptoProvider
from src.authentication.dns.dns_resolver import CachedDNSResolver
from src.authentication.engine import AuthenticationVerificationEngine
from src.authentication.models import AuthenticationVerification
from src.database.models import RawEmail
from src.orchestrator.engine import OrchestratorEngine
from src.parsing.models import HeaderAddressDTO, ParsedEmail
from src.security_intelligence.threat_intel.framework import ThreatIntelTargetType
from src.threat_intel.manager import ThreatIntelManager
from src.threat_intel.providers.whois import WHOISProvider
from src.transmission.models import SenderIdentityAnalysisDTO, TransmissionAnalysis


def test_arc_validation_with_crypto_and_dns() -> None:
    """Verify ARC validator chain evaluation using RSACryptoProvider and CachedDNSResolver."""
    crypto = RSACryptoProvider()
    dns = CachedDNSResolver()

    # Parsed email with valid ARC headers
    parsed = ParsedEmail(
        raw_email_id=uuid4(),
        account_id=uuid4(),
        tenant_id=uuid4(),
        message_id="msg_arc_test",
        internet_message_id="<msg_arc_test@company.com>",
        sender=HeaderAddressDTO(name="User", address="user@company.com"),
        date=datetime.now(UTC),
        raw_headers={
            "arc-seal": [
                "i=1; a=rsa-sha256; cv=pass; d=company.com; s=arc1; b=dGVzdF9zaWduYXR1cmU="
            ],
            "arc-authentication-results": [
                "i=1; mx.google.com; dkim=pass; spf=pass; dmarc=pass"
            ],
            "arc-message-signature": [
                "i=1; a=rsa-sha256; c=relaxed/relaxed; d=company.com; s=arc1; b=c2lnbmF0dXJl"
            ],
        },
    )

    arc_res = validate_arc_chain(parsed, crypto_provider=crypto, dns_resolver=dns)

    assert arc_res.chain_valid is True
    assert arc_res.instance_count == 1
    assert arc_res.latest_result == "pass"


def test_whois_provider_domain_age_metadata() -> None:
    """Verify WHOISProvider exposes domain_age_days and is_newly_registered metadata with malicious=False."""
    provider = WHOISProvider()

    # Lookup new domain (<30 days)
    obs_new = provider.lookup(
        "new-domain.com", ThreatIntelTargetType.DOMAIN, timeout_seconds=2.0
    )
    assert obs_new is not None
    assert (
        obs_new.malicious is False
    )  # Mandatory rule: newly registered domain MUST NOT automatically be malicious
    assert obs_new.threat_category == "newly_registered_domain"
    assert obs_new.metadata is not None
    assert obs_new.metadata["is_newly_registered"] is True
    assert obs_new.metadata["domain_age_days"] == 10

    # Lookup established domain
    obs_est = provider.lookup(
        "google.com", ThreatIntelTargetType.DOMAIN, timeout_seconds=2.0
    )
    assert obs_est is not None
    assert obs_est.malicious is False
    assert obs_est.threat_category == "established_domain"
    assert obs_est.metadata is not None
    assert obs_est.metadata["is_newly_registered"] is False
    assert obs_est.metadata["domain_age_days"] == 5000


def test_threat_intel_manager_registration_whois() -> None:
    """Verify WHOISProvider is registered in ThreatIntelManager provider registry."""
    manager = ThreatIntelManager()
    whois_p = manager.registry.get_provider("whois/rdap")

    assert whois_p is not None
    assert whois_p.provider_name == "WHOIS/RDAP"

    observations = manager.lookup_indicator(
        "phishing-portal.com", ThreatIntelTargetType.DOMAIN
    )
    assert len(observations) >= 1
    whois_obs = [o for o in observations if o.provider_name == "WHOIS/RDAP"]
    assert len(whois_obs) == 1
    assert whois_obs[0].metadata is not None
    assert "domain_age_days" in whois_obs[0].metadata


def test_module13_orchestrator_integration() -> None:
    """Verify Module 12 Pipeline Orchestrator executes Module 13 ARC and WHOIS enhancements cleanly."""

    async def _run() -> None:
        engine = OrchestratorEngine()

        raw_email = RawEmail(
            id=uuid4(),
            account_id=uuid4(),
            tenant_id=uuid4(),
            message_id="msg_mod13_test",
            internet_message_id="<msg_mod13_test@company.com>",
            raw_eml_data=b"ARC-Seal: i=1; a=rsa-sha256; cv=pass; d=company.com; s=arc1; b=c2ln\r\nFrom: user@company.com\r\nTo: rcpt@company.com\r\nSubject: Test\r\n\r\nBody",
        )

        result = await engine.analyze_email(raw_email)

        assert result.analysis_id is not None
        assert result.auth_verification.arc.chain_valid is True
        assert result.threat_intel is not None
        assert result.risk_assessment is not None
        assert result.decision_plan is not None

    asyncio.run(_run())
