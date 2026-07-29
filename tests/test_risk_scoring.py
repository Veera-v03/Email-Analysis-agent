"""Regression tests for weighted, explainable risk scoring."""

from __future__ import annotations

from src.models.agent import AgentState, ToolEvidence
from src.models.email import EmailHeader, EmailInput
from src.planner.explainability import ExplainabilityEngine
from src.planner.reasoning import ReasoningEngine
from src.planner.risk_scoring import RiskScoringEngine


def _state() -> AgentState:
    return AgentState.create(
        parsed_email=EmailInput(
            header=EmailHeader(
                message_id="<risk@test>",
                sender="sender@test.example",
                recipients=["recipient@test.example"],
                subject="Risk test",
                sent_at="2026-07-29T00:00:00Z",
            ),
            body_text="test",
        )
    )


def test_weighted_risk_score_is_bounded_and_explainable() -> None:
    state = _state().with_evidence(
        (
            ToolEvidence(
                category="sender_spf",
                detail="SPF failed.",
                metadata={"severity": "high"},
            ),
            ToolEvidence(
                category="url_reputation",
                detail="Malicious URL.",
                metadata={"severity": "critical"},
            ),
        )
    )
    score = RiskScoringEngine().score(state.evidence.items)

    assert score.score == 34.0
    assert score.risk_level == "medium"
    assert [item["factor"] for item in score.breakdown] == ["authentication", "url"]


def test_reasoning_and_report_expose_score_breakdown() -> None:
    state = _state().with_evidence(
        ToolEvidence(
            category="campaign_correlation",
            detail="Campaign matched.",
            metadata={"severity": "high"},
        )
    )
    verdict = ReasoningEngine().reason(state)
    report = ExplainabilityEngine().generate_report(state, verdict)

    assert verdict.risk_score == 9.6
    assert verdict.score_breakdown[0]["factor"] == "campaign"
    assert report.risk_score == verdict.risk_score
