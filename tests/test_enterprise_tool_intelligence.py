"""Tests for optional enterprise sender and URL intelligence enrichment."""

from __future__ import annotations

from src.analyzers.agent.enterprise_intelligence import (
    EnterpriseIntelligenceService,
    IntelligenceObservation,
)
from src.analyzers.agent.tools.sender_tool import SenderTool
from src.analyzers.agent.tools.url_tool import URLTool
from src.models.agent import AgentState, ToolExecutionStatus
from src.models.email import EmailHeader, EmailInput


class StaticProvider:
    """Deterministic enterprise provider fixture."""

    provider_name = "virustotal"

    def __init__(self, malicious: bool = False) -> None:
        self.calls = 0
        self.malicious = malicious

    def lookup(
        self,
        subject: str,
        *,
        timeout_seconds: float,
    ) -> IntelligenceObservation:
        self.calls += 1
        return IntelligenceObservation(
            provider_name=self.provider_name,
            summary=f"Reputation lookup completed for {subject}.",
            malicious=self.malicious,
            confidence=0.91,
            metadata={"lookup_timeout_seconds": timeout_seconds},
        )


class TimeoutProvider:
    """Provider fixture that exercises bounded retry diagnostics."""

    provider_name = "urlhaus"

    def __init__(self) -> None:
        self.calls = 0

    def lookup(
        self,
        subject: str,
        *,
        timeout_seconds: float,
    ) -> IntelligenceObservation:
        self.calls += 1
        raise TimeoutError("simulated timeout")


def _state(body: str = "No links") -> AgentState:
    return AgentState.create(
        parsed_email=EmailInput(
            header=EmailHeader(
                message_id="<enterprise-intel@example.test>",
                sender="Alerts <alerts@example.test>",
                recipients=["recipient@example.test"],
                subject="Security notice",
                sent_at="2026-07-29T10:00:00Z",
            ),
            body_text=body,
        )
    )


def test_sender_tool_appends_enterprise_infrastructure_evidence() -> None:
    provider = StaticProvider(malicious=True)
    tool = SenderTool(
        enterprise_intelligence=EnterpriseIntelligenceService((provider,))
    )

    result = tool.execute(_state())

    assert result.status is ToolExecutionStatus.COMPLETED
    evidence = next(
        item for item in result.evidence if item.category == "sender_enterprise_virustotal"
    )
    assert evidence.metadata["domain"] == "example.test"
    assert evidence.metadata["severity"] == "high"
    assert provider.calls == 1


def test_url_tool_appends_enterprise_url_reputation_evidence() -> None:
    provider = StaticProvider(malicious=True)
    tool = URLTool(
        enterprise_intelligence=EnterpriseIntelligenceService((provider,))
    )

    result = tool.execute(_state("Visit https://example.test/login now."))

    assert result.status is ToolExecutionStatus.COMPLETED
    evidence = next(
        item for item in result.evidence if item.category == "url_enterprise_virustotal"
    )
    assert evidence.metadata["url"] == "https://example.test/login"
    assert evidence.metadata["severity"] == "high"


def test_enterprise_intelligence_caches_provider_observations() -> None:
    provider = StaticProvider()
    service = EnterpriseIntelligenceService((provider,), cache_ttl_seconds=60.0)

    first = service.enrich("example.test")
    second = service.enrich("example.test")

    assert first.from_cache is False
    assert second.from_cache is True
    assert provider.calls == 1


def test_enterprise_intelligence_reports_timeout_after_configured_retries() -> None:
    provider = TimeoutProvider()
    service = EnterpriseIntelligenceService((provider,), retries=1)

    result = service.enrich("https://example.test/login")

    assert provider.calls == 2
    assert result.observations == ()
    assert result.diagnostics[0].provider_name == "urlhaus"
    assert result.diagnostics[0].reason == "Provider lookup timed out."
