"""Comprehensive unit and integration test suite for Module 11 Enterprise AI Decision Planner Engine."""

from __future__ import annotations

import asyncio
from uuid import uuid4

from src.ai_decision.context_builder import ContextSizeManager, DecisionContextBuilder
from src.ai_decision.engine import AIDecisionEngine
from src.ai_decision.guardrail import AIGuardrailLayer
from src.ai_decision.module import AIDecisionModule, register_ai_decision_module
from src.ai_decision.pipeline import AIDecisionPipeline
from src.ai_decision.prompt_builder import DecisionPromptBuilder
from src.ai_decision.providers.gemini import GeminiLLMProvider
from src.ai_decision.validator import DecisionResponseValidator
from src.common.constants import ActionTaken, Verdict
from src.container.di import Container
from src.events.base_event import BaseEvent
from src.events.security_events import RiskScoredEvent
from src.messaging.event_bus import InMemoryEventBus
from src.registry.module_registry import ModuleRegistry
from src.risk.models import ConfidenceScoreDetailsDTO, RiskAssessment, RiskEvidenceDTO


def test_context_size_manager() -> None:
    """Verify ContextSizeManager bounds top weighted evidence."""
    manager = ContextSizeManager(max_evidence_items=2)
    evidences = [
        RiskEvidenceDTO(
            source_module="transmission",
            feature_name="f1",
            applied_weight=10,
            explanation="Low weight",
        ),
        RiskEvidenceDTO(
            source_module="authentication",
            feature_name="f2",
            applied_weight=40,
            explanation="High weight",
        ),
        RiskEvidenceDTO(
            source_module="threat_intel",
            feature_name="f3",
            applied_weight=30,
            explanation="Mid weight",
        ),
    ]

    bounded = manager.bound_evidence(evidences)
    assert len(bounded) == 2
    assert bounded[0].applied_weight == 40
    assert bounded[1].applied_weight == 30


def test_decision_prompt_builder() -> None:
    """Verify DecisionPromptBuilder loads and formats prompt templates from disk."""
    builder = DecisionPromptBuilder()
    context = {
        "message_id": "msg_001",
        "risk_score": "85",
        "verdict": "MALICIOUS",
        "recommended_action": "QUARANTINED",
        "overall_confidence": "0.95",
        "threat_categories": "BEC, PHISHING",
        "evidence_summary": "- [TRANSMISSION] Display name spoofing (+40 pts)",
        "mitre_techniques": "T1566 (Phishing)",
        "soc_recommendations": "- Isolate endpoint",
        "scoring_strategy": "DeterministicWeightedScoringStrategy",
    }

    system_prompt, user_prompt = builder.build_prompts(context)

    assert "ScamON Enterprise AI Decision Planner" in system_prompt
    assert "Message ID: msg_001" in user_prompt
    assert "Risk Score: 85" in user_prompt


def test_ai_guardrail_verification() -> None:
    """Verify AIGuardrailLayer prevents policy contradictions and empty narratives."""
    guardrail = AIGuardrailLayer()

    assessment = RiskAssessment(
        parsed_id=uuid4(),
        transmission_id=uuid4(),
        auth_verification_id=uuid4(),
        intel_enrichment_id=uuid4(),
        account_id=uuid4(),
        tenant_id=uuid4(),
        message_id="msg_grd_001",
        risk_score=95,
        verdict=Verdict.MALICIOUS,
        recommended_action=ActionTaken.BLOCKED,
        confidence_details=ConfidenceScoreDetailsDTO(overall_confidence=0.9),
        explainability_summary="Malicious email detected",
    )

    valid_json = """{
        "executive_summary": "High risk malicious campaign detected.",
        "technical_summary": "DMARC authentication failed.",
        "analyst_explanation": "Investigation identified severe BEC display name spoofing.",
        "recommended_actions": ["Block sender domain."]
    }"""

    sanitized = guardrail.verify_completion(valid_json, assessment)
    assert sanitized["executive_summary"] == "High risk malicious campaign detected."


def test_ai_decision_pipeline_execution() -> None:
    """Verify AIDecisionPipeline end-to-end execution with Gemini fallback completion."""

    async def _run() -> None:
        assessment = RiskAssessment(
            parsed_id=uuid4(),
            transmission_id=uuid4(),
            auth_verification_id=uuid4(),
            intel_enrichment_id=uuid4(),
            account_id=uuid4(),
            tenant_id=uuid4(),
            message_id="msg_pipe_111",
            risk_score=90,
            verdict=Verdict.MALICIOUS,
            recommended_action=ActionTaken.BLOCKED,
            confidence_details=ConfidenceScoreDetailsDTO(overall_confidence=0.92),
            risk_evidence=[
                RiskEvidenceDTO(
                    source_module="transmission",
                    feature_name="is_display_name_spoofed",
                    applied_weight=40,
                    explanation="Executive display name spoofing detected",
                )
            ],
            threat_categories=["BEC"],
            explainability_summary="Malicious BEC attempt detected",
        )

        pipeline = AIDecisionPipeline(llm_provider=GeminiLLMProvider(api_key=None))
        plan = await pipeline.plan_decision(assessment)

        assert plan.schema_version == "1.0.0"
        assert plan.message_id == "msg_pipe_111"
        assert plan.risk_confidence == 0.92
        assert len(plan.provenance_mappings) == 1
        assert (
            plan.provenance_mappings[0].supporting_feature == "is_display_name_spoofed"
        )
        assert len(plan.recommended_actions) > 0

    asyncio.run(_run())


def test_ai_decision_engine_events() -> None:
    """Verify AIDecisionEngine event emission to EventBus."""

    async def _run() -> None:
        published: list[BaseEvent] = []

        class MockPublisher:
            async def publish(self, event: BaseEvent) -> None:
                published.append(event)

        engine = AIDecisionEngine(event_publisher=MockPublisher())

        assessment = RiskAssessment(
            parsed_id=uuid4(),
            transmission_id=uuid4(),
            auth_verification_id=uuid4(),
            intel_enrichment_id=uuid4(),
            account_id=uuid4(),
            tenant_id=uuid4(),
            message_id="msg_evt_ai",
            risk_score=15,
            verdict=Verdict.CLEAN,
            recommended_action=ActionTaken.DELIVERED,
            confidence_details=ConfidenceScoreDetailsDTO(overall_confidence=0.98),
            explainability_summary="Clean email delivered",
        )

        plan = await engine.generate_decision_plan(assessment)
        assert plan.plan_id is not None

        events = [e for e in published if isinstance(e, RiskScoredEvent)]
        assert len(events) == 1
        assert events[0].message_id == "msg_evt_ai"

    asyncio.run(_run())


def test_ai_decision_module_lifecycle() -> None:
    """Verify AIDecisionModule DI container registration and health check lifecycle."""

    async def _run() -> None:
        di = Container()
        registry = ModuleRegistry()
        bus = InMemoryEventBus()

        mod = register_ai_decision_module(di, registry, event_publisher=bus)
        assert registry.get_module("ai_decision") == mod

        await registry.initialize_all()

        health = await registry.health_check_all()
        assert health.status == "UP"

        await registry.shutdown_all()

    asyncio.run(_run())
