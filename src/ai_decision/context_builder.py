"""Decision Context Builder and Context Size Manager for selecting top risk evidence."""

from __future__ import annotations

from typing import Any

from src.risk.models import RiskAssessment, RiskEvidenceDTO


class ContextSizeManager:
    """Selects and bounds top relevant evidence when context size exceeds character/token budget limits."""

    def __init__(
        self, max_evidence_items: int = 5, max_context_chars: int = 4000
    ) -> None:
        self.max_evidence_items = max_evidence_items
        self.max_context_chars = max_context_chars

    def bound_evidence(
        self, evidence_list: list[RiskEvidenceDTO]
    ) -> list[RiskEvidenceDTO]:
        """Sort evidence by weight points and return top items within size budget."""
        if not evidence_list:
            return []

        sorted_evidence = sorted(
            evidence_list, key=lambda e: e.applied_weight, reverse=True
        )
        return sorted_evidence[: self.max_evidence_items]


class DecisionContextBuilder:
    """Extracts relevant evidence and constructs structured prompt context from RiskAssessment."""

    def __init__(self, size_manager: ContextSizeManager | None = None) -> None:
        self.size_manager = size_manager or ContextSizeManager()

    def build_context_dict(self, assessment: RiskAssessment) -> dict[str, Any]:
        """Extract filtered context variables dictionary for prompt template formatting."""
        bounded_evidence = self.size_manager.bound_evidence(assessment.risk_evidence)

        evidence_formatted = (
            "\n".join(
                [
                    f"- [{e.source_module.upper()}] {e.explanation} (+{e.applied_weight} pts, confidence: {e.confidence:.2f})"
                    for e in bounded_evidence
                ]
            )
            or "- Zero malicious risk evidence identified."
        )

        mitre_formatted = (
            ", ".join(
                [
                    f"{t.get('id', '')} ({t.get('name', '')})"
                    for t in assessment.mitre_techniques
                ]
            )
            or "None"
        )

        soc_formatted = (
            "\n".join([f"- {r}" for r in assessment.soc_recommendations])
            or "- Deliver to inbox normally."
        )

        return {
            "message_id": assessment.message_id,
            "risk_score": str(assessment.risk_score),
            "verdict": assessment.verdict.value,
            "recommended_action": assessment.recommended_action.value,
            "overall_confidence": f"{assessment.confidence_details.overall_confidence:.2f}",
            "threat_categories": ", ".join(assessment.threat_categories) or "None",
            "evidence_summary": evidence_formatted,
            "mitre_techniques": mitre_formatted,
            "soc_recommendations": soc_formatted,
            "scoring_strategy": assessment.scoring_strategy,
        }
