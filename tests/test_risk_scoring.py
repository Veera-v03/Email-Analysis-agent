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


def test_brand_impersonation_produces_non_zero_risk_score() -> None:
    # Impersonating Microsoft from an unrelated domain
    state = AgentState.create(
        parsed_email=EmailInput(
            header=EmailHeader(
                message_id="<phish-brand@test>",
                sender="admin@microsoft-secure-login.com",
                recipients=["target@enterprise.com"],
                subject="Microsoft 365 Security Alert",
                sent_at="2026-08-31T00:00:00Z",
            ),
            body_text="Please verify your account.",
        )
    )
    verdict = ReasoningEngine().reason(state)
    report = ExplainabilityEngine().generate_report(state, verdict)

    assert verdict.risk_score > 0.0
    assert report.risk_score == verdict.risk_score
    factors = [b["factor"] for b in verdict.score_breakdown]
    assert "impersonation" in factors
    assert verdict.risk_level in {"high", "critical"}


def test_social_engineering_produces_non_zero_risk_score() -> None:
    # Severe urgency & credential harvesting language without brand mismatch
    state = AgentState.create(
        parsed_email=EmailInput(
            header=EmailHeader(
                message_id="<phish-soc@test>",
                sender="security-notification@internal.com",
                recipients=["target@enterprise.com"],
                subject="System Notification",
                sent_at="2026-08-31T00:00:00Z",
            ),
            body_text="Your account will be suspended immediately within 24 hours. Provide your password to verify your account.",
        )
    )
    verdict = ReasoningEngine().reason(state)
    report = ExplainabilityEngine().generate_report(state, verdict)

    assert verdict.risk_score > 0.0
    assert report.risk_score == verdict.risk_score
    factors = [b["factor"] for b in verdict.score_breakdown]
    assert "social_engineering" in factors


def test_combined_critical_phishing_produces_material_score_and_breakdown() -> None:
    # PayPal credential harvesting with urgent suspension language
    state = AgentState.create(
        parsed_email=EmailInput(
            header=EmailHeader(
                message_id="<phish-combined@test>",
                sender="security@paypa1-support.com",
                recipients=["victim@enterprise.com"],
                subject="URGENT: Your PayPal account will be suspended",
                sent_at="2026-08-31T00:00:00Z",
            ),
            body_text=(
                "Your PayPal account has been restricted. You must verify immediately "
                "within 24 hours or your account will be permanently suspended. "
                "Please provide your username, password, and card information."
            ),
        )
    )
    verdict = ReasoningEngine().reason(state)
    report = ExplainabilityEngine().generate_report(state, verdict)

    assert verdict.risk_level == "critical"
    assert report.classification == "PHISHING / MALICIOUS"
    assert report.recommended_priority == "P1"
    assert verdict.confidence >= 0.88
    # Materially high score combining impersonation (18.0) and social engineering (18.0) = 36.0
    assert verdict.risk_score >= 36.0
    assert report.risk_score == verdict.risk_score
    factors = [b["factor"] for b in verdict.score_breakdown]
    assert "impersonation" in factors
    assert "social_engineering" in factors
    assert len(report.score_breakdown) >= 2


def test_benign_email_remains_low_risk_and_zero_score() -> None:
    # Standard benign internal email
    state = AgentState.create(
        parsed_email=EmailInput(
            header=EmailHeader(
                message_id="<benign@test>",
                sender="alice@example.com",
                recipients=["bob@example.com"],
                subject="Team meeting reminder",
                sent_at="2026-08-31T00:00:00Z",
            ),
            body_text="Hi team, reminder for our project sync tomorrow at 10am. Thanks, Alice.",
        )
    )
    verdict = ReasoningEngine().reason(state)
    report = ExplainabilityEngine().generate_report(state, verdict)

    assert verdict.risk_level == "low"
    assert report.classification == "CLEAN / SAFE"
    assert report.recommended_priority == "P4"
    assert verdict.risk_score == 0.0
    assert verdict.score_breakdown == ()
    assert report.score_breakdown == ()
