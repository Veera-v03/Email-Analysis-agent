"""Explainability Generator producing human-readable audit explanations from RiskEvidenceDTO list."""

from __future__ import annotations

from src.common.constants import ActionTaken, Verdict
from src.risk.models import RiskEvidenceDTO


class ExplainabilityGenerator:
    """Generates structured, human-auditable explainability text for risk assessments."""

    def generate_summary(
        self,
        risk_score: int,
        verdict: Verdict,
        action: ActionTaken,
        evidence_list: list[RiskEvidenceDTO],
    ) -> str:
        """Generate formatted explainability summary string."""
        if not evidence_list or verdict == Verdict.CLEAN:
            return (
                f"Incident assessed as {verdict.value} (Risk Score: {risk_score}/100). "
                f"Recommended Action: {action.value}. Zero malicious risk indicators detected."
            )

        top_evidence = sorted(
            evidence_list, key=lambda e: e.applied_weight, reverse=True
        )[:3]
        evidence_text = "; ".join(
            [f"{e.explanation} (+{e.applied_weight} pts)" for e in top_evidence]
        )

        return (
            f"Incident assessed as {verdict.value} (Risk Score: {risk_score}/100). "
            f"Recommended Action: {action.value}. Top risk factors: {evidence_text}."
        )
