"""Focused tests for normalized intelligence and campaign evidence integration."""

from __future__ import annotations

from src.analyzers.agent.tools.threat_intelligence_tool import ThreatIntelligenceTool
from src.models.agent import AgentState, ToolEvidence
from src.models.email import EmailHeader, EmailInput
from src.planner.reasoning import ReasoningEngine
from src.security_intelligence.threat_intel.framework import (
    ThreatIntelligenceFramework,
    ThreatIntelObservation,
    ThreatIntelTargetType,
)


class _StaticProvider:
    provider_name = "virustotal"

    def __init__(self) -> None:
        self.calls = 0

    def lookup(
        self,
        target: str,
        target_type: ThreatIntelTargetType,
        *,
        timeout_seconds: float,
    ) -> ThreatIntelObservation:
        self.calls += 1
        return ThreatIntelObservation(
            provider_name=self.provider_name,
            target=target,
            target_type=target_type,
            malicious=True,
            confidence=0.95,
            threat_category="phishing",
            detection_count=12,
        )


class _TimeoutProvider:
    provider_name = "urlhaus"

    def lookup(
        self,
        target: str,
        target_type: ThreatIntelTargetType,
        *,
        timeout_seconds: float,
    ) -> ThreatIntelObservation | None:
        raise TimeoutError


def _state() -> AgentState:
    return AgentState.create(
        parsed_email=EmailInput(
            header=EmailHeader(
                message_id="<intel@test>",
                sender="sender@phishing-portal.com",
                recipients=["recipient@test"],
                subject="Verify account",
                sent_at="2026-07-29T00:00:00Z",
            ),
            body_text="Open https://phishing-portal.com/login immediately.",
        )
    )


def test_framework_normalizes_evidence_and_caches_provider_calls() -> None:
    provider = _StaticProvider()
    framework = ThreatIntelligenceFramework([provider])

    first = framework.to_evidence("phishing-portal.com", ThreatIntelTargetType.DOMAIN)
    second = framework.to_evidence("phishing-portal.com", ThreatIntelTargetType.DOMAIN)

    assert provider.calls == 1
    assert first[0].metadata["detection_count"] == 12
    assert second[0].metadata["from_cache"] is True


def test_framework_degrades_to_diagnostic_after_timeout() -> None:
    evidence = ThreatIntelligenceFramework([_TimeoutProvider()]).to_evidence(
        "https://example.test", ThreatIntelTargetType.URL
    )

    assert evidence[0].category == "threat_intelligence_diagnostic"


def test_threat_intelligence_tool_and_reasoning_consume_provider_match() -> None:
    result = ThreatIntelligenceTool(
        framework=ThreatIntelligenceFramework([_StaticProvider()])
    ).execute(_state())
    state = _state().with_tool_result(result)
    verdict = ReasoningEngine().reason(state)

    assert any(
        item["indicator"] == "External Threat Intelligence Match"
        for item in verdict.evidence_correlation
    )
    assert (
        "external threat-intelligence provider matches" in verdict.security_explanation
    )


def test_reasoning_explains_campaign_evidence() -> None:
    state = _state().with_evidence(
        ToolEvidence(
            category="campaign_correlation",
            detail="Campaign campaign_123 matched historical phishing cases.",
            metadata={"severity": "high", "confidence": 0.8},
        )
    )
    verdict = ReasoningEngine().reason(state)

    assert any(
        item["indicator"] == "Campaign Correlation"
        for item in verdict.evidence_correlation
    )
    assert "tenant campaign correlation evidence" in verdict.security_explanation
