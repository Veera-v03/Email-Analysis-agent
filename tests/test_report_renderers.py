"""Explainability report presentation regression tests."""

from __future__ import annotations

from src.models.agent import AgentState, ToolEvidence
from src.models.email import EmailHeader, EmailInput
from src.planner.explainability import ExplainabilityEngine
from src.planner.reasoning import ReasoningOutput
from src.planner.report_renderers import (
    HtmlReportRenderer,
    JsonReportRenderer,
    MarkdownReportRenderer,
)


def test_enterprise_report_fields_and_renderers() -> None:
    state = AgentState.create(
        parsed_email=EmailInput(
            header=EmailHeader(
                message_id="<report@test>",
                sender="sender@test.example",
                recipients=["recipient@test.example"],
                subject="Urgent verification",
                sent_at="2026-07-29T00:00:00Z",
            ),
            body_text="Visit https://phishing-portal.com/login",
        )
    ).with_evidence(
        ToolEvidence(
            category="url_reputation",
            detail="Malicious URL identified.",
            metadata={"severity": "high"},
        )
    )
    reasoning = ReasoningOutput(
        summary="Malicious URL detected.",
        confidence=0.85,
        risk_level="high",
        recommended_action="Quarantine the email.",
        security_explanation="URL reputation evidence is high risk.",
        analyst_notes="- URL reputation: malicious",
        risk_score=14.4,
        score_breakdown=(
            {
                "factor": "url",
                "points": 14.4,
                "weight": 18.0,
                "evidence_id": "ev_test",
                "reason": "Malicious URL identified.",
            },
        ),
    )
    report = ExplainabilityEngine().generate_report(state, reasoning)

    assert report.executive_summary
    assert report.recommended_priority == "P2"
    assert report.confidence_breakdown
    assert "# Investigation:" in MarkdownReportRenderer().render(report)
    assert "<html>" in HtmlReportRenderer().render(report)
    assert '"risk_score"' in JsonReportRenderer().render(report)
