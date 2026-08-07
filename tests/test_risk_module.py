"""Comprehensive unit and integration test suite for Module 10 Enterprise Risk Assessment Engine."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from uuid import uuid4

from src.authentication.models import (
    AuthenticationVerification,
    DMARCResultDTO,
    SPFResultDTO,
)
from src.common.constants import ActionTaken, Verdict
from src.container.di import Container
from src.events.base_event import BaseEvent
from src.events.security_events import RiskScoredEvent
from src.messaging.event_bus import InMemoryEventBus
from src.parsing.models import HeaderAddressDTO, ParsedEmail
from src.registry.module_registry import ModuleRegistry
from src.risk.confidence_fusion import ConfidenceFusionEngine
from src.risk.engine import RiskAssessmentEngine
from src.risk.models import ConfidenceScoreDetailsDTO, RiskPolicyConfig
from src.risk.module import RiskAssessmentModule, register_risk_module
from src.risk.pipeline import RiskAssessmentPipeline
from src.risk.policy import PolicyEvaluator
from src.risk.registry import RiskFeatureRegistry
from src.risk.strategies.deterministic import DeterministicWeightedScoringStrategy
from src.threat_intel.models import ConfidenceScoreDTO, ThreatIntelEnrichmentResult
from src.transmission.models import SenderIdentityAnalysisDTO, TransmissionAnalysis


def test_policy_evaluator_thresholds() -> None:
    """Verify PolicyEvaluator maps score thresholds to Verdict and ActionTaken."""
    policy = PolicyEvaluator(config=RiskPolicyConfig())

    v_clean, a_clean = policy.evaluate_policy(15)
    assert v_clean == Verdict.CLEAN
    assert a_clean == ActionTaken.DELIVERED

    v_susp, a_susp = policy.evaluate_policy(45)
    assert v_susp == Verdict.SUSPICIOUS
    assert a_susp == ActionTaken.BANNER_INJECTED

    v_quar, a_quar = policy.evaluate_policy(75)
    assert v_quar == Verdict.MALICIOUS
    assert a_quar == ActionTaken.QUARANTINED

    v_block, a_block = policy.evaluate_policy(95)
    assert v_block == Verdict.MALICIOUS
    assert a_block == ActionTaken.BLOCKED


def test_deterministic_scoring_strategy() -> None:
    """Verify DeterministicWeightedScoringStrategy produces correct score and rich RiskEvidenceDTO."""
    strategy = DeterministicWeightedScoringStrategy()
    config = RiskPolicyConfig()

    features = {
        "is_display_name_spoofed": True,  # 40 pts
        "malicious_ioc_count": 2,  # 35 pts
        "dmarc_result": "FAIL",  # 30 pts
    }

    score, evidence, categories = strategy.calculate_score(features, config)

    assert score == 100  # Capped at 100
    assert len(evidence) == 3
    assert any(e.feature_name == "is_display_name_spoofed" for e in evidence)
    assert "BEC" in categories
    assert "PHISHING" in categories


def test_confidence_fusion_engine() -> None:
    """Verify ConfidenceFusionEngine fuses multi-dimensional confidence metrics."""
    fusion = ConfidenceFusionEngine()

    parsed = ParsedEmail(
        raw_email_id=uuid4(),
        account_id=uuid4(),
        tenant_id=uuid4(),
        message_id="msg_fuse_001",
        internet_message_id="<msg001@company.com>",
        sender=HeaderAddressDTO(name="User", address="user@company.com"),
        date=datetime.now(UTC),
    )

    transmission = TransmissionAnalysis(
        parsed_id=parsed.parsed_id,
        raw_email_id=parsed.raw_email_id,
        account_id=parsed.account_id,
        tenant_id=parsed.tenant_id,
        message_id="msg_fuse_001",
        internet_message_id="<msg001@company.com>",
        originating_ip="10.0.0.1",
        sender_identity=SenderIdentityAnalysisDTO(
            from_address="user@company.com", from_domain="company.com"
        ),
    )

    auth = AuthenticationVerification(
        parsed_id=parsed.parsed_id,
        transmission_id=transmission.analysis_id,
        account_id=parsed.account_id,
        tenant_id=parsed.tenant_id,
        message_id="msg_fuse_001",
        internet_message_id="<msg001@company.com>",
        spf=SPFResultDTO(result="PASS", domain="company.com"),
        dmarc=DMARCResultDTO(result="PASS", domain="company.com"),
    )

    intel = ThreatIntelEnrichmentResult(
        parsed_id=parsed.parsed_id,
        transmission_id=transmission.analysis_id,
        auth_verification_id=auth.verification_id,
        account_id=parsed.account_id,
        tenant_id=parsed.tenant_id,
        message_id="msg_fuse_001",
        overall_confidence=ConfidenceScoreDTO(confidence=1.0),
    )

    details = fusion.fuse_confidence(parsed, transmission, auth, intel, [])
    assert details.overall_confidence > 0.8
    assert details.feature_completeness == 1.0


def test_risk_assessment_pipeline() -> None:
    """Verify RiskAssessmentPipeline end-to-end execution, explainability, and MITRE mapping."""
    parsed = ParsedEmail(
        raw_email_id=uuid4(),
        account_id=uuid4(),
        tenant_id=uuid4(),
        message_id="msg_risk_777",
        internet_message_id="<msg777@evil.com>",
        sender=HeaderAddressDTO(name="CEO Jane", address="jane@evil.com"),
        body_plain="Urgent wire transfer",
        date=datetime.now(UTC),
    )

    transmission = TransmissionAnalysis(
        parsed_id=parsed.parsed_id,
        raw_email_id=parsed.raw_email_id,
        account_id=parsed.account_id,
        tenant_id=parsed.tenant_id,
        message_id="msg_risk_777",
        internet_message_id="<msg777@evil.com>",
        originating_ip="198.51.100.42",
        sender_identity=SenderIdentityAnalysisDTO(
            from_address="jane@evil.com",
            from_domain="evil.com",
            is_display_name_spoofed=True,
            is_reply_to_mismatched=True,
        ),
    )

    auth = AuthenticationVerification(
        parsed_id=parsed.parsed_id,
        transmission_id=transmission.analysis_id,
        account_id=parsed.account_id,
        tenant_id=parsed.tenant_id,
        message_id="msg_risk_777",
        internet_message_id="<msg777@evil.com>",
        spf=SPFResultDTO(result="FAIL", domain="evil.com"),
        dmarc=DMARCResultDTO(result="FAIL", domain="evil.com"),
    )

    intel = ThreatIntelEnrichmentResult(
        parsed_id=parsed.parsed_id,
        transmission_id=transmission.analysis_id,
        auth_verification_id=auth.verification_id,
        account_id=parsed.account_id,
        tenant_id=parsed.tenant_id,
        message_id="msg_risk_777",
        malicious_ioc_count=1,
        overall_confidence=ConfidenceScoreDTO(confidence=0.95),
        matched_feeds=["VirusTotal"],
        threat_categories=["BEC"],
    )

    pipeline = RiskAssessmentPipeline()
    assessment = pipeline.assess_risk(parsed, transmission, auth, intel)

    assert assessment.risk_score >= 90
    assert assessment.verdict == Verdict.MALICIOUS
    assert assessment.recommended_action == ActionTaken.BLOCKED
    assert len(assessment.risk_evidence) >= 3
    assert len(assessment.mitre_techniques) > 0
    assert "Incident assessed as MALICIOUS" in assessment.explainability_summary


def test_risk_engine_events() -> None:
    """Verify RiskAssessmentEngine event emission to EventBus."""

    async def _run() -> None:
        published: list[BaseEvent] = []

        class MockPublisher:
            async def publish(self, event: BaseEvent) -> None:
                published.append(event)

        engine = RiskAssessmentEngine(event_publisher=MockPublisher())

        parsed = ParsedEmail(
            raw_email_id=uuid4(),
            account_id=uuid4(),
            tenant_id=uuid4(),
            message_id="msg_evt_risk",
            internet_message_id="<evt_risk@company.com>",
            sender=HeaderAddressDTO(name="User", address="user@company.com"),
            date=datetime.now(UTC),
        )

        transmission = TransmissionAnalysis(
            parsed_id=parsed.parsed_id,
            raw_email_id=parsed.raw_email_id,
            account_id=parsed.account_id,
            tenant_id=parsed.tenant_id,
            message_id="msg_evt_risk",
            internet_message_id="<evt_risk@company.com>",
            originating_ip="10.0.0.5",
            sender_identity=SenderIdentityAnalysisDTO(
                from_address="user@company.com", from_domain="company.com"
            ),
        )

        auth = AuthenticationVerification(
            parsed_id=parsed.parsed_id,
            transmission_id=transmission.analysis_id,
            account_id=parsed.account_id,
            tenant_id=parsed.tenant_id,
            message_id="msg_evt_risk",
            internet_message_id="<evt_risk@company.com>",
            spf=SPFResultDTO(result="PASS", domain="company.com"),
            dmarc=DMARCResultDTO(result="PASS", domain="company.com"),
        )

        intel = ThreatIntelEnrichmentResult(
            parsed_id=parsed.parsed_id,
            transmission_id=transmission.analysis_id,
            auth_verification_id=auth.verification_id,
            account_id=parsed.account_id,
            tenant_id=parsed.tenant_id,
            message_id="msg_evt_risk",
            overall_confidence=ConfidenceScoreDTO(confidence=1.0),
        )

        assessment = await engine.assess_risk(parsed, transmission, auth, intel)
        assert assessment.assessment_id is not None

        risk_events = [e for e in published if isinstance(e, RiskScoredEvent)]
        assert len(risk_events) == 1
        assert risk_events[0].message_id == "msg_evt_risk"
        assert risk_events[0].verdict == Verdict.CLEAN

    asyncio.run(_run())


def test_risk_module_lifecycle() -> None:
    """Verify RiskAssessmentModule DI container registration and health check lifecycle."""

    async def _run() -> None:
        di = Container()
        registry = ModuleRegistry()
        bus = InMemoryEventBus()

        mod = register_risk_module(di, registry, event_publisher=bus)
        assert registry.get_module("risk_assessment") == mod

        await registry.initialize_all()

        health = await registry.health_check_all()
        assert health.status == "UP"

        await registry.shutdown_all()

    asyncio.run(_run())
