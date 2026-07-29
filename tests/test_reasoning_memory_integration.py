"""Regression coverage for historical-memory use by the reasoning engine."""

from __future__ import annotations

from src.memory.models.memory_models import (
    InvestigationMemory,
    MemorySearchResult,
    MemoryType,
)
from src.models.agent import AgentState
from src.models.email import EmailHeader, EmailInput
from src.models.evidence import Evidence, EvidenceSeverity
from src.planner.reasoning import ReasoningEngine


class StaticMemoryRetrieval:
    """Expose the existing investigation-retrieval API with fixed results."""

    def __init__(self, results: list[MemorySearchResult]) -> None:
        self.results = results
        self.calls: list[dict[str, object]] = []

    def find_similar_investigations(
        self,
        *,
        subject: str,
        sender: str,
        body_summary: str | None = None,
        top_k: int = 5,
    ) -> list[MemorySearchResult]:
        self.calls.append(
            {
                "subject": subject,
                "sender": sender,
                "body_summary": body_summary,
                "top_k": top_k,
            }
        )
        return self.results


def _state() -> AgentState:
    email = EmailInput(
        header=EmailHeader(
            message_id="<current@example.test>",
            sender="billing@fraud.test",
            recipients=["recipient@example.test"],
            subject="Urgent wire transfer request",
            sent_at="2026-07-29T10:00:00Z",
        ),
        body_text="Review the invoice at https://fraud.test/pay now.",
    )
    evidence = Evidence(
        category="url_reputation",
        title="Suspicious URL",
        description="A suspicious payment URL was identified.",
        severity=EvidenceSeverity.HIGH,
        source="url_tool",
    )
    return AgentState.create(parsed_email=email).model_copy(
        update={"evidence": AgentState.create().evidence.add(evidence)}
    )


def _historical_result(
    memory_id: str,
    *,
    similarity: float,
    classification: str,
    risk_level: str,
    sender: str = "billing@fraud.test",
) -> MemorySearchResult:
    return MemorySearchResult(
        memory_id=memory_id,
        memory_type=MemoryType.INVESTIGATION,
        similarity_score=similarity,
        record=InvestigationMemory(
            memory_id=memory_id,
            email_id=f"<{memory_id}@example.test>",
            subject="Urgent wire transfer request",
            sender=sender,
            classification=classification,
            risk_level=risk_level,
            summary="Phishing invoice campaign using https://fraud.test/pay.",
        ),
    )


def test_reasoning_is_unchanged_when_no_historical_matches_exist() -> None:
    state = _state()
    baseline = ReasoningEngine().reason(state)
    retrieval = StaticMemoryRetrieval([])

    result = ReasoningEngine(retrieval).reason(state)

    assert result == baseline
    assert len(retrieval.calls) == 1


def test_reasoning_incorporates_one_similar_phishing_investigation() -> None:
    state = _state()
    baseline = ReasoningEngine().reason(state)
    retrieval = StaticMemoryRetrieval(
        [
            _historical_result(
                "historical-phish-1",
                similarity=0.91,
                classification="phishing",
                risk_level="high",
            )
        ]
    )

    result = ReasoningEngine(retrieval).reason(state)

    assert result.confidence == baseline.confidence + 0.03
    assert "historical-phish-1" in result.recommended_action
    assert "high-similarity historical phishing investigation matches" in (
        result.security_explanation
    )
    assert any(
        correlation["indicator"] == "Historical Investigation Match"
        and correlation["evidence_id"] == "historical-phish-1"
        for correlation in result.evidence_correlation
    )


def test_multiple_similar_phishing_investigations_surface_campaign_context() -> None:
    state = _state()
    baseline = ReasoningEngine().reason(state)
    retrieval = StaticMemoryRetrieval(
        [
            _historical_result(
                "historical-phish-1",
                similarity=0.94,
                classification="phishing",
                risk_level="high",
            ),
            _historical_result(
                "historical-phish-2",
                similarity=0.90,
                classification="phishing",
                risk_level="critical",
            ),
        ]
    )

    result = ReasoningEngine(retrieval).reason(state)

    assert result.confidence == baseline.confidence + 0.06
    assert "repeated historical phishing campaign" in result.security_explanation
    assert any(
        correlation["indicator"] == "Historical Phishing Campaign Correlation"
        for correlation in result.evidence_correlation
    )


def test_repeated_historical_campaign_elevates_anotherwise_low_risk_email() -> None:
    state = AgentState.create(parsed_email=_state().parsed_email)
    retrieval = StaticMemoryRetrieval(
        [
            _historical_result(
                "historical-phish-1",
                similarity=0.94,
                classification="phishing",
                risk_level="high",
            ),
            _historical_result(
                "historical-phish-2",
                similarity=0.90,
                classification="phishing",
                risk_level="critical",
            ),
        ]
    )

    result = ReasoningEngine(retrieval).reason(state)

    assert result.risk_level == "medium"
    assert "possible campaign" in result.summary
    assert "Quarantine email" in result.recommended_action


def test_conflicting_historical_investigations_do_not_adjust_confidence() -> None:
    state = _state()
    baseline = ReasoningEngine().reason(state)
    retrieval = StaticMemoryRetrieval(
        [
            _historical_result(
                "historical-phish",
                similarity=0.93,
                classification="phishing",
                risk_level="high",
            ),
            _historical_result(
                "historical-safe",
                similarity=0.89,
                classification="safe",
                risk_level="low",
            ),
        ]
    )

    result = ReasoningEngine(retrieval).reason(state)

    assert result.confidence == baseline.confidence
    assert "conflicting high-similarity historical investigation outcomes" in (
        result.security_explanation
    )
    assert any(
        correlation["indicator"] == "Conflicting Historical Investigation Matches"
        for correlation in result.evidence_correlation
    )


def test_empty_memory_database_preserves_existing_reasoning() -> None:
    state = _state()
    retrieval = StaticMemoryRetrieval([])

    assert ReasoningEngine(retrieval).reason(state) == ReasoningEngine().reason(state)
